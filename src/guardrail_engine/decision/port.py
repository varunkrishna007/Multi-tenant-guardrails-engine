"""The ``DecisionModel`` port: the only way the engine talks to a decision model.

Adapters (Gemini, a self-hosted classifier, the test fake) never raise for
expected provider outcomes. They return one of three results, matching the
branches in the Guard Service sketch:

* :class:`Answered`: per question key, either a valid answer or a recorded problem; plus usage
* :class:`SafetyBlocked`: the provider refused the content (HTTP 400 ``"code": "safety"`` or
  ``"prohibited_content"``);
  the Guard Service records this as a ``block`` decision, not an error
* :class:`Failed`: no usable answer (timeout, rate limit, limit exceeded); the Guard
  Service applies the guard point's fail mode

Typical use::

    match await model.decide(input, questions):
        case Answered(answers=answers): ...
        case SafetyBlocked(): ...
        case Failed(kind=kind): ...

Adapters build results with :func:`guardrail_engine.decision.response.parse_response`.
A bad answer for one key (missing, wrong type, out of range) does not fail the call: it is
recorded in ``Answered.problems`` and the Guard Service resolves it per rule by the rule's
layer (PF-6). Retry policy belongs to the gateway (M1-04), so it is not on the result type.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from enum import StrEnum
from typing import Annotated, Any, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, field_validator

from guardrail_engine.decision.types import Answer, NoulAnswer, Question, Usage

REFUSAL_PROHIBITED_CONTENT = "prohibited_content"
"""``SafetyBlocked.reason`` when the provider refused the input before scoring (HTTP 400 code
``prohibited_content``, any case; M1-13, R10). Stable: callers such as harness tripwires may
depend on it. Detect any refusal by ``isinstance(result, SafetyBlocked)``; ``reason`` tells
which kind."""
REFUSAL_SAFETY = "safety"
"""``SafetyBlocked.reason`` for the documented HTTP 400 ``"code": "safety"``. A
safety refusal named by another structured field carries that field's value instead (e.g.
``"SAFETY_BLOCKED"`` from a google.rpc status); see the Gemini adapter. Stable, as above."""

REFUSAL_BLOCKLIST = "blocklist"
REFUSAL_CONTENT_BLOCKED = "content_blocked"
REFUSAL_IMAGE_SAFETY = "image_safety"
"""``SafetyBlocked.reason`` for the other refusal codes Google's Decisions API guide lists
(``safety``, ``prohibited_content``, ``blocklist``, ``image_safety`` and ``content_blocked``;
read on 2026-11-17). Matched exactly, like ``prohibited_content``. None of the three has been
seen live: they are mapped from Google's documentation alone, and tested on constructed
fixtures. Stable, as above."""
REFUSAL_CODES = frozenset(
    {
        REFUSAL_PROHIBITED_CONTENT,
        REFUSAL_BLOCKLIST,
        REFUSAL_CONTENT_BLOCKED,
        REFUSAL_IMAGE_SAFETY,
    }
)
"""The exact refusal codes that map to ``SafetyBlocked``. ``safety`` is the fifth documented
code and is matched by the adapter's wider rule (any structured field naming safety)."""

_CODE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}")
UNRECOGNISED_CODE = "unrecognised"
"""What :func:`recorded_code` records in place of a value that isn't code-shaped."""


def recorded_code(value: object) -> str | None:
    """A structured code as it may be recorded: the value itself if it is
    code-shaped (letters, digits and ``_.:-``, at most 64 characters, e.g.
    ``API_KEY_INVALID``, ``admission_wait``, ``prohibited_content``), otherwise
    ``"unrecognised"``. So a provider that puts free text where a code belongs can't get it
    into a verdict, an audit record, a span, a log line or a metric label: the result never
    holds a space, a newline or ``=``.

    Defined here, at the bottom layer, so the gateway (M1-13 metering) and the Guard Service
    (M1-06 audit) bound provider codes the same way; ``guard.verdict`` re-exports it."""
    if value is None:
        return None
    return value if isinstance(value, str) and _CODE.fullmatch(value) else UNRECOGNISED_CODE


# ---------------------------------------------------------------- unrecognised 400 labels
# M1-15: the label an unrecognised provider error is counted and logged
# under (``provider_error_unrecognised``). Stricter than :func:`recorded_code`, which keeps
# the provider's case and ``.:-`` for ``failure_reason`` in verdicts, audit records and spans
# and is deliberately left as it is. These labels are metric labels only.

ERROR_LABEL_NO_CODE = "_no_code"
"""A 400 whose JSON body carries no error code (or an empty one, or only a numeric google.rpc
code with no ``status``)."""
ERROR_LABEL_NOT_JSON = "_not_json"
"""A 400 whose body isn't JSON at all (a proxy's HTML page, say)."""
ERROR_LABEL_MALFORMED = "_malformed"
"""A provider code that, after casefolding, isn't 1-64 characters of ``[a-z0-9_]``, or that
spells one of the engine's own ``_``-prefixed placeholder labels."""
ERROR_LABEL_PLACEHOLDERS = frozenset(
    {ERROR_LABEL_NO_CODE, ERROR_LABEL_NOT_JSON, ERROR_LABEL_MALFORMED}
)
"""The placeholder labels a ``Failed.unrecognised_code`` may hold besides a provider code.
The gateway adds one more of its own, ``_overflow`` (its 64-distinct-label cap)."""
RESERVED_ERROR_LABELS = ERROR_LABEL_PLACEHOLDERS | {"_overflow"}
"""Labels the engine owns. A provider code that spells one of them counts as
``_malformed``, so it can never be mistaken for the engine's own bucket."""
_ERROR_LABEL = re.compile(r"[a-z0-9_]{1,64}")


def provider_error_label(code: str) -> str:
    """The metric label for an unrecognised provider error **code as the provider sent
    it**: casefolded, then kept if it is 1-64 characters of ``[a-z0-9_]`` and isn't one of
    :data:`RESERVED_ERROR_LABELS`, otherwise :data:`ERROR_LABEL_MALFORMED`. So case variants
    share one label (and one place under the gateway's cap), and provider text can't grow
    the label set without bound, carry content, or forge a log line."""
    folded = code.casefold()
    if folded in RESERVED_ERROR_LABELS or not _ERROR_LABEL.fullmatch(folded):
        return ERROR_LABEL_MALFORMED
    return folded


def bounded_error_label(value: object) -> str | None:
    """Re-bound a label that should already have come from :func:`provider_error_label` (or
    be a placeholder), whoever built it: a placeholder in :data:`ERROR_LABEL_PLACEHOLDERS`
    and a valid label are returned unchanged, so applying it twice never moves a label to
    another bucket; anything else is labelled as a provider code would be. ``None`` stays
    ``None`` (nothing to count)."""
    if value is None:
        return None
    if not isinstance(value, str):
        return ERROR_LABEL_MALFORMED
    if value in ERROR_LABEL_PLACEHOLDERS:
        return value
    return provider_error_label(value)


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class FailureKind(StrEnum):
    TIMEOUT = "timeout"
    """No answer within the deadline."""
    RATE_LIMITED = "rate_limited"
    """HTTP 429."""
    LIMIT_EXCEEDED = "limit_exceeded"
    """HTTP 400 naming a limit. A config bug: the validator should have prevented it."""
    UNAVAILABLE = "unavailable"
    """Transient unavailability: HTTP 5xx or a connection error."""
    AUTH = "auth"
    """The provider rejected the credentials: an invalid, expired or blocked key, a disabled
    service, or HTTP 401/403. Never retried; the gateway treats it as page-now (M1-04)."""
    OTHER = "other"
    """Anything unclassified, including a response that can't be parsed."""


class ProblemKind(StrEnum):
    MISSING = "missing"
    """No answer for the key."""
    WRONG_TYPE = "wrong_type"
    """The answer's ``type`` differs from the question's."""
    OUT_OF_RANGE = "out_of_range"
    """A number outside its bounds, or an undeclared option or level."""
    INVALID = "invalid"
    """Any other malformation: not an object, a required field missing, a non-number..."""


class AnswerProblem(_Frozen):
    """Why one question key has no usable answer. ``raw`` is the raw answer as received."""

    kind: ProblemKind
    detail: str
    raw: Any = None


class Answered(_Frozen):
    """``answers`` holds the valid answers and ``problems`` the rest. Built by
    ``parse_response``, every question key is in exactly one of the two."""

    outcome: Literal["answered"] = "answered"
    answers: dict[str, Answer]
    problems: dict[str, AnswerProblem] = Field(default_factory=dict)
    usage: Usage | None
    """Token usage, or None when the response's ``usage`` block was missing or invalid.
    Metering never decides whether traffic is blocked, so a bad usage block doesn't fail
    the call. The gateway counts and alerts on ``usage is None``."""
    usage_problem: str | None = None
    """Why ``usage`` is None."""

    @property
    def ok(self) -> bool:
        """True when every key has a valid answer."""
        return not self.problems

    def noul(self, key: str) -> float:
        """The probability for ``noul`` question ``key``."""
        answer = self.answers[key]
        if not isinstance(answer, NoulAnswer):
            raise TypeError(f"answer {key!r} is {answer.type!r}, not 'noul'")
        return answer.noul


class SafetyBlocked(_Frozen):
    """The provider refused the content: HTTP 400 ``safety``, or one of the refusal codes
    Google documents (``prohibited_content``, ``blocklist``, ``image_safety``,
    ``content_blocked``; M1-13). Never retried; always a block (PF-12, R10)."""

    outcome: Literal["safety_blocked"] = "safety_blocked"
    message: str | None = None
    """The provider's own text. Free text: never copied into a verdict or audit record; the
    Guard Service logs it at DEBUG only, truncated. It may echo the input."""
    reason: str | None = None
    """The provider's structured refusal code, when it gave one: one of :data:`REFUSAL_CODES`,
    :data:`REFUSAL_SAFETY`, or another structured field that named safety. Unlike
    ``message``, this is recorded (as the verdict's ``failure_reason``)."""


class Failed(_Frozen):
    outcome: Literal["failed"] = "failed"
    kind: FailureKind
    message: str | None = None
    key: str | None = None
    """For LIMIT_EXCEEDED: the question key the provider named, if any."""
    reason: str | None = None
    """The provider's own reason or status, e.g. ``"API_KEY_INVALID"``, when it gave one."""
    # ``message`` is free text (provider wording, or a raw error body): it goes to logs at
    # most, never into a verdict or audit record.
    unrecognised_code: str | None = None
    """For a 400 that fell to ``OTHER`` because its error code is not one the adapter knows:
    the metric label for it (M1-15): the code casefolded, or ``_malformed``, ``_no_code`` or
    ``_not_json`` (see :func:`provider_error_label`). Bounded by :func:`bounded_error_label`
    here whoever builds the result. The gateway counts it per tenant and guard point (M1-13).
    Never the provider's message."""

    retry_delay_s: float | None = None
    """For RATE_LIMITED: the delay the provider asked for in a structured ``RetryInfo``
    error detail (google.rpc), in seconds, when it gave one (M1-15, R8). Never derived
    from message text. A value that isn't a finite number >= 0 is dropped (None). The gateway
    passes it on as ``retry_after_ms``, clamped."""

    @field_validator("unrecognised_code", mode="before")
    @classmethod
    def _bounded(cls, value: object) -> str | None:
        return bounded_error_label(value)

    @field_validator("retry_delay_s", mode="before")
    @classmethod
    def _sane_delay(cls, value: object) -> float | None:
        if isinstance(value, bool) or not isinstance(value, int | float):
            return None
        return float(value) if 0 <= value < float("inf") else None


DecisionResult = Annotated[Answered | SafetyBlocked | Failed, Field(discriminator="outcome")]


@runtime_checkable
class DecisionModel(Protocol):
    """Port to a decision model.

    ``decide`` is a coroutine. Implementations must be safe to call from many concurrent
    tasks on one event loop, and must tolerate cancellation: the gateway enforces
    deadlines by cancelling the call.
    """

    @property
    def model_id(self) -> str:
        """Identifier recorded in the audit log, e.g. ``"gemini-decision-1"``."""
        ...

    async def decide(self, input: str, questions: Mapping[str, Question]) -> DecisionResult:
        """Ask every question about the same ``input`` in one call.

        On :class:`Answered`, each key of ``questions`` is in exactly one of ``answers``
        (valid, of the matching type) or ``problems``.
        """
        ...
