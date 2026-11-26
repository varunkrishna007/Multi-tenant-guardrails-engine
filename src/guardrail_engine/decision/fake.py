"""A deterministic, scriptable ``DecisionModel`` for tests. It makes no network calls.

Defaults: every ``noul`` answers ``default_noul`` (0.01, so "no" on everything), every
``choice`` answers its first option, and every ``score`` answers its lowest level (0). A
``choice`` or ``score`` answer is a one-hot distribution on the picked option or level.

How each call is resolved, in order:

1. Latency: the call awaits ``asyncio.sleep(latency)``, taken from the ``slow_next`` queue,
   otherwise ``latency_s`` (default 0). This always yields to the event loop, so concurrent
   calls interleave. It is also a cancellation point, so a caller's deadline
   (``asyncio.timeout``) can expire mid-call like a real slow provider. A call cancelled
   here consumes no scripted outcome and is not recorded.
2. Request limits (:func:`~guardrail_engine.decision.limits.validate_request`): question
   count, key format, and the estimated tokens against the 262,144-token context. A
   violation returns ``Failed(LIMIT_EXCEEDED, key=...)``, as the real API returns HTTP 400.
3. Queued one-shot outcomes are consumed one per call, first in, first out:
   ``safety_block_next``, ``timeout_next``, ``rate_limit_next``, ``fail_next``, ``push``,
   and the malformed-response path below.
4. A sticky outcome set with ``always(...)`` is returned until it is cleared.
5. Otherwise the fake builds a well-formed raw response body. For each key the value is
   taken from the ``responder`` if it returns non-``None``; otherwise from the per-key
   script; otherwise from the default.

Every answer, well-formed or not, goes through the shared parser
(:func:`~guardrail_engine.decision.response.parse_response`) that the real adapter uses.

**Malformed-response path (AC-M1-8).** Scripted values are range-checked as they are set
(a test bug should fail loudly), so malformed answers are produced only on purpose, by
editing the raw body before it is parsed:

* ``malformed_next(missing=..., wrong_type=..., out_of_range=..., raw_answers=...)``
* ``raw_response_next(body)``, which parses ``body`` verbatim.

The parser then reports each bad key in ``Answered.problems``.

Every completed call is recorded in ``calls``. The fake is safe for concurrent use from
tasks on one event loop; it is not thread-safe.
"""

from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from guardrail_engine.decision.limits import (
    CONFIDENCE_MAX,
    CONFIDENCE_MIN,
    NOUL_MAX,
    NOUL_MIN,
    DecisionLimitError,
    validate_request,
)
from guardrail_engine.decision.port import DecisionResult, Failed, FailureKind, SafetyBlocked
from guardrail_engine.decision.response import parse_response
from guardrail_engine.decision.types import ChoiceQuestion, NoulQuestion, Question
from guardrail_engine.tokens import estimate_question_tokens, estimate_tokens

Responder = Callable[[str, str, Question], float | str | int | None]
"""``(input, key, question) -> value or None``. A float for ``noul``, an option key for
``choice``, a level index for ``score``. Return ``None`` to fall through to the script."""

ScriptedOutcome = SafetyBlocked | Failed

OUT_OF_RANGE_NOUL = 1.2
UNDECLARED_OPTION = "__undeclared_option__"


@dataclass(frozen=True)
class FakeCall:
    input: str
    questions: dict[str, Question]
    result: DecisionResult


@dataclass(frozen=True)
class _RawEdit:
    missing: frozenset[str] = frozenset()
    wrong_type: frozenset[str] = frozenset()
    out_of_range: Mapping[str, Any] = field(default_factory=dict)
    raw_answers: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class _RawBody:
    body: Any


_Queued = SafetyBlocked | Failed | _RawEdit | _RawBody


def _check_noul(p: float) -> float:
    if not NOUL_MIN <= p <= NOUL_MAX:
        raise ValueError(f"noul probability must be in [{NOUL_MIN}, {NOUL_MAX}], got {p}")
    return p


def _check_confidence(c: float) -> float:
    if not CONFIDENCE_MIN <= c <= CONFIDENCE_MAX:
        raise ValueError(f"confidence must be in [0, 1], got {c}")
    return c


class FakeDecisionModel:
    model_id = "fake-decision"

    def __init__(
        self,
        *,
        default_noul: float = NOUL_MIN,
        default_confidence: float = 0.9,
        noul: Mapping[str, float] | None = None,
        choice: Mapping[str, str] | None = None,
        score: Mapping[str, int] | None = None,
        confidence: Mapping[str, float] | None = None,
        responder: Responder | None = None,
        latency_s: float = 0.0,
    ) -> None:
        self.default_noul = _check_noul(default_noul)
        self.default_confidence = _check_confidence(default_confidence)
        self._noul = {k: _check_noul(v) for k, v in (noul or {}).items()}
        self._choice = dict(choice or {})
        self._score = dict(score or {})
        self._confidence = {k: _check_confidence(v) for k, v in (confidence or {}).items()}
        self.responder = responder
        self.latency_s = latency_s
        self._latencies: deque[float] = deque()
        self._queue: deque[_Queued] = deque()
        self._sticky: ScriptedOutcome | None = None
        self.calls: list[FakeCall] = []

    # ------------------------------------------------------------------ scripting answers

    def set_noul(self, key: str, p: float) -> FakeDecisionModel:
        self._noul[key] = _check_noul(p)
        return self

    def set_choice(self, key: str, option: str) -> FakeDecisionModel:
        self._choice[key] = option
        return self

    def set_score(self, key: str, level: int) -> FakeDecisionModel:
        """Answer ``score`` question ``key`` with level index ``level`` (0 = lowest)."""
        self._score[key] = level
        return self

    def set_confidence(self, key: str, confidence: float) -> FakeDecisionModel:
        self._confidence[key] = _check_confidence(confidence)
        return self

    # ------------------------------------------------------------------ scripting outcomes

    def push(self, *outcomes: ScriptedOutcome) -> FakeDecisionModel:
        """Queue one-shot outcomes, consumed one per call before answering."""
        self._queue.extend(outcomes)
        return self

    def safety_block_next(
        self, times: int = 1, message: str | None = None, reason: str | None = None
    ) -> FakeDecisionModel:
        return self.push(*[SafetyBlocked(message=message, reason=reason)] * times)

    def timeout_next(self, times: int = 1) -> FakeDecisionModel:
        return self.fail_next(FailureKind.TIMEOUT, times)

    def rate_limit_next(self, times: int = 1) -> FakeDecisionModel:
        return self.fail_next(FailureKind.RATE_LIMITED, times)

    def fail_next(
        self, kind: FailureKind, times: int = 1, message: str | None = None
    ) -> FakeDecisionModel:
        """Queue ``times`` failures of any kind."""
        return self.push(*[Failed(kind=kind, message=message)] * times)

    def always(self, outcome: ScriptedOutcome | None) -> FakeDecisionModel:
        """Return ``outcome`` on every call (after the queue drains) until called with None."""
        self._sticky = outcome
        return self

    def slow_next(self, seconds: float, times: int = 1) -> FakeDecisionModel:
        """Make the next ``times`` calls take ``seconds`` before answering."""
        self._latencies.extend([seconds] * times)
        return self

    # ------------------------------------------------------------------ malformed responses

    def malformed_next(
        self,
        *,
        missing: Iterable[str] = (),
        wrong_type: Iterable[str] = (),
        out_of_range: Iterable[str] | Mapping[str, Any] = (),
        raw_answers: Mapping[str, Any] | None = None,
    ) -> FakeDecisionModel:
        """Make the next call's raw response malformed, then parse it as usual.

        * ``missing``: drop these keys' answers.
        * ``wrong_type``: answer these keys with an answer of a different type.
        * ``out_of_range``: put an out-of-range value in these keys' main field. A ``noul``
          gets 1.2, a ``choice`` gets an undeclared option, and a ``score`` gets one level
          above the top. Pass a mapping ``{key: value}`` to choose the value, e.g. a noul
          of 1.0.
        * ``raw_answers``: replace these keys' raw answers verbatim.

        Keys not named are answered normally.
        """
        if isinstance(out_of_range, Mapping):
            oor = dict(out_of_range)
        else:
            oor = dict.fromkeys(out_of_range)
        groups = {
            "missing": set(missing),
            "wrong_type": set(wrong_type),
            "out_of_range": set(oor),
            "raw_answers": set(raw_answers or {}),
        }
        seen: dict[str, str] = {}
        for group, keys in groups.items():
            for key in sorted(keys):
                if key in seen:
                    raise ValueError(
                        f"malformed_next: key {key!r} is in both {seen[key]!r} and {group!r}"
                    )
                seen[key] = group
        missing, wrong_type = groups["missing"], groups["wrong_type"]
        self._queue.append(
            _RawEdit(
                missing=frozenset(missing),
                wrong_type=frozenset(wrong_type),
                out_of_range=oor,
                raw_answers=dict(raw_answers or {}),
            )
        )
        return self

    def raw_response_next(self, body: Any) -> FakeDecisionModel:
        """Make the next call parse ``body`` verbatim as the provider's response."""
        self._queue.append(_RawBody(body))
        return self

    # ------------------------------------------------------------------ the port

    async def decide(self, input: str, questions: Mapping[str, Question]) -> DecisionResult:
        questions = dict(questions)
        latency = self._latencies.popleft() if self._latencies else self.latency_s
        await asyncio.sleep(latency)
        result = self._resolve(input, questions)
        self.calls.append(FakeCall(input=input, questions=questions, result=result))
        return result

    def _resolve(self, input: str, questions: dict[str, Question]) -> DecisionResult:
        try:
            validate_request(input, questions)
        except DecisionLimitError as e:
            return Failed(kind=FailureKind.LIMIT_EXCEEDED, message=e.reason, key=e.key)

        scripted = self._queue.popleft() if self._queue else self._sticky
        if isinstance(scripted, _RawBody):
            return parse_response(scripted.body, questions)
        if isinstance(scripted, SafetyBlocked | Failed):
            return scripted

        body = self.build_raw_response(input, questions)
        if isinstance(scripted, _RawEdit):
            _apply_edit(body["answers"], questions, scripted)
        return parse_response(body, questions)

    # ------------------------------------------------------------------ raw bodies

    def build_raw_response(self, input: str, questions: Mapping[str, Question]) -> dict:
        """The well-formed raw response body this fake would send for this call."""
        tokens = estimate_tokens(input) + estimate_question_tokens(questions)
        return {
            "answers": {key: self._raw_answer(input, key, q) for key, q in questions.items()},
            "usage": {
                "total_tokens": tokens,
                "total_input_tokens": tokens,
                "input_tokens_by_modality": [{"modality": "text", "tokens": tokens}],
                "total_output_tokens": 0,
            },
        }

    def _raw_answer(self, input: str, key: str, q: Question) -> dict:
        value = self.responder(input, key, q) if self.responder else None
        confidence = self._confidence.get(key, self.default_confidence)

        if isinstance(q, NoulQuestion):
            p = value if value is not None else self._noul.get(key, self.default_noul)
            if isinstance(p, bool) or not isinstance(p, int | float):
                raise TypeError(f"responder returned {p!r} for noul question {key!r}")
            return {"type": "noul", "noul": _check_noul(float(p)), "confidence": confidence}

        if isinstance(q, ChoiceQuestion):
            picked = value if value is not None else self._choice.get(key, next(iter(q.criteria)))
            if picked not in q.criteria:
                raise ValueError(
                    f"scripted choice {picked!r} for {key!r} is not one of {list(q.criteria)}"
                )
            return {
                "type": "choice",
                "choice": picked,
                "probabilities": {opt: float(opt == picked) for opt in q.criteria},
                "confidence": confidence,
            }

        level = value if value is not None else self._score.get(key, 0)
        if isinstance(level, bool) or not isinstance(level, int):
            raise TypeError(f"scripted score for {key!r} must be a level index, got {level!r}")
        if not 0 <= level < len(q.criteria):
            raise ValueError(
                f"scripted score level {level} for {key!r} is outside 0..{len(q.criteria) - 1}"
            )
        return {
            "type": "score",
            "score": float(level),
            "probabilities": {str(i): float(i == level) for i in range(len(q.criteria))},
            "legend": {str(i): desc for i, desc in enumerate(q.criteria)},
            "confidence": confidence,
        }


def _apply_edit(answers: dict[str, Any], questions: Mapping[str, Question], edit: _RawEdit) -> None:
    named = edit.missing | edit.wrong_type | edit.out_of_range.keys()
    unknown = sorted(named - questions.keys())
    if unknown:
        raise ValueError(f"malformed_next names keys that are not in this call: {unknown}")
    for key in edit.missing:
        answers.pop(key, None)
    for key in edit.wrong_type:
        if questions[key].type == "noul":
            answers[key] = {
                "type": "choice",
                "choice": "yes",
                "probabilities": {"yes": 1.0},
                "confidence": 0.9,
            }
        else:
            answers[key] = {"type": "noul", "noul": 0.5, "confidence": 0.5}
    for key, value in edit.out_of_range.items():
        q = questions[key]
        if isinstance(q, NoulQuestion):
            answers[key]["noul"] = OUT_OF_RANGE_NOUL if value is None else value
        elif isinstance(q, ChoiceQuestion):
            answers[key]["choice"] = UNDECLARED_OPTION if value is None else value
        else:
            answers[key]["score"] = float(len(q.criteria)) if value is None else value
    answers.update(edit.raw_answers)


MARKER_BLOCK = "[mix:block]"
MARKER_ESCALATE = "[mix:escalate]"
MARKER_FAIL = "[mix:fail]"
MARKER_REFUSE = "[mix:refuse]"
_INJECTION_KEY = "p__inj_direct"


class MarkedFakeDecisionModel(FakeDecisionModel):
    """A fake that decides by what the text says, so two processes given the same text decide
    alike (a test or a load run that compares modes needs that). The text carries a marker:
    ``[mix:block]`` scores the floor's injection rule over its block line, ``[mix:escalate]`` over
    its escalate line, ``[mix:fail]`` is an ``unavailable`` failure and ``[mix:refuse]`` a provider
    safety refusal. Text with no marker is allowed."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(responder=self._by_marker, **kwargs)

    @staticmethod
    def _by_marker(text: str, key: str, question: Question) -> float | None:
        if key != _INJECTION_KEY:
            return None
        if MARKER_BLOCK in text:
            return 0.95
        if MARKER_ESCALATE in text:
            return 0.6
        return None

    async def decide(self, input: str, questions: Mapping[str, Question]) -> DecisionResult:
        if MARKER_REFUSE in input:
            if self.latency_s > 0:
                await asyncio.sleep(self.latency_s)
            return SafetyBlocked(reason="safety")
        if MARKER_FAIL in input:
            if self.latency_s > 0:
                await asyncio.sleep(self.latency_s)
            return Failed(kind=FailureKind.UNAVAILABLE)
        return await super().decide(input, questions)
