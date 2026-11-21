"""The draft's validate and test endpoints (M2-04, M2-05), on top of the draft service.

Both act on the tenant's **stored draft** and take the tenant only from the authorizer's
decision scope, like every other handler.

**Validate (M2-04)** re-runs the compiler on the stored draft against today's catalog (a floor
or pack change since the write can invalidate a draft that was valid) and returns every error,
or, for a valid draft, the compiled question preview per guard point and the cost figures: the
estimated API tokens of the largest call the guard point can make against the 16,000-token
content budget (PF-10) and what that call costs at $0.10 per 1M input tokens. Nothing is sent
to a model.

**Test (M2-05)** runs inline samples through the draft exactly as a production check would
(deterministic checks in AC-G1 order, redaction, render, one decision call, fusion) and
answers, per sample, the decision, whether the sample's ``expected`` verdict was met, and the
probabilities of the **tenant's own and pack rules**. A **floor** rule shows only what
production shows (its key, action and mode when it fires), never its probability: the
probability would let content be tuned just under the floor's thresholds. A sample may name a
``tool`` (for a ``tool_call`` allow-list). It sends **each sample to the model** (paid calls), so:

* the role is ``guardrail_reviewer``;
* a request is at most :data:`MAX_SAMPLES` samples, and its body at most ``MAX_DRAFT_BYTES``
  (the route's own bound), and a tenant has **one test run at a time**
  (``DraftTestInProgressError``, 429);
* nothing is written to the production audit sink, and the calls are metered under the usage
  class ``test`` so production figures never include them; they reserve from the same token
  bucket and counters as production, in a fourth priority class below ``tool_result``; the
  response reports the run's input tokens and estimated cost from the provider's usage figures;
* the engine counts a running test as in-flight work, so shutdown waits for it, and refuses a
  new one once it has started.

**A stored golden set (M2-06)** can stand in for ``samples``: ``{"guard_point", "golden_set":
"gs_...", "offset"?}`` runs that set's examples at the guard point (**never a quarantined
row**: see :mod:`guardrail_engine.admin.golden`) (at most :data:`MAX_SAMPLES`
from ``offset``, in upload order), each with its label as ``expected``. Another tenant's set is
indistinguishable from one that doesn't exist (404). The report says how many examples the set
has at that guard point and how many ran, so a larger set is run in pages.
"""

from __future__ import annotations

import asyncio
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

from guardrail_engine.admin.drafts import StoredDraft
from guardrail_engine.admin.golden import GoldenSetNotFoundError, ScopedGoldenStores
from guardrail_engine.admin.service import (
    DraftError,
    DraftInvalidError,
    DraftServiceError,
    NoDraftError,
    TenantUnavailableError,
    _convert,
    _scope_of,
)
from guardrail_engine.admin.vocabulary import strings_tripwire
from guardrail_engine.authz.authorizer import AuthzDecision
from guardrail_engine.guard.policy_cache import GuardPointPolicy
from guardrail_engine.guard.tenants import TenantProfile
from guardrail_engine.guard.verdict import Verdict
from guardrail_engine.policy.catalog import Catalog, PlatformSettings
from guardrail_engine.policy.compiler import PolicyCompiler
from guardrail_engine.policy.document import ParsedBundle, read_bundle
from guardrail_engine.policy.errors import PolicyInvalidError
from guardrail_engine.policy.json_document import parse_json_text
from guardrail_engine.policy.schema import GUARD_POINTS
from guardrail_engine.tenant_scope import TenantScope

VALIDATE_DRAFT = ("POST", "/v1/tenants/{tid}/guardrails/draft/validate")
TEST_DRAFT = ("POST", "/v1/tenants/{tid}/guardrails/draft/test")

PRICE_USD_PER_1M_INPUT_TOKENS = 0.10
"""§Why GD1, price: $0.10 per 1M input tokens; output is free."""
MAX_SAMPLES = 50
MAX_SAMPLE_ID_CHARS = 64
TEST_CONCURRENCY = 4
EXPECTED = ("allow", "escalate", "block")
_SAMPLE_FIELDS = {"id", "content", "expected", "tool"}
MAX_TOOL_CHARS = 128
_REQUEST_FIELDS = {"guard_point", "samples", "golden_set", "offset"}
_GOLDEN_ID = re.compile(r"gs_[0-9a-f]{16}")


class DraftTestInProgressError(DraftServiceError):
    """The tenant already has a test run going (HTTP 429)."""


class EvaluatorUnavailableError(DraftServiceError):
    """The engine can't evaluate drafts now (it is shutting down; HTTP 503)."""


class DraftEvaluator(Protocol):
    """What the test endpoint needs from the engine: compile a draft into guard-point
    policies, and run content through one of them (:meth:`GuardService.evaluate_draft`)."""

    def compile(
        self, tenant_id: str, parsed: ParsedBundle, profile: TenantProfile
    ) -> Mapping[str, GuardPointPolicy]: ...

    async def evaluate(
        self,
        scope: TenantScope,
        policy: GuardPointPolicy,
        content: str,
        tool: str | None = None,
        usage_class: str = "test",
    ) -> Verdict:
        """Raises :class:`EvaluatorUnavailableError` when the engine is not accepting."""
        ...


# --------------------------------------------------------------------------- validate


@dataclass(frozen=True, slots=True)
class GuardPointPreview:
    guard_point: str
    enabled: bool
    question_count: int
    question_budget: int
    questions: tuple[dict[str, Any], ...]
    """Each compiled question as it is sent, with its key, layer, source and thresholds."""
    max_content_tokens: int
    content_api_tokens: int
    question_api_tokens: int
    api_tokens: int
    """The estimate for the largest call this guard point can make (content at its cap)."""
    token_budget: int
    within_budget: bool
    headroom_tokens: int
    est_cost_usd_per_check: float
    """``api_tokens`` at the price per 1M input tokens: the cost of a maximum-size check."""


@dataclass(frozen=True, slots=True)
class ValidationReport:
    draft_hash: str
    valid: bool
    errors: tuple[DraftError, ...]
    guard_points: dict[str, GuardPointPreview] = field(default_factory=dict)
    token_budget: int = 0
    price_usd_per_1m_input_tokens: float = PRICE_USD_PER_1M_INPUT_TOKENS
    calibration: dict[str, Any] | None = None
    """M4-01: the threshold suggestions for the draft's tenant rules (from stored scores; nothing
    is sent to a model), with the targets, bundle hash, floor version and draft they were
    computed from. None when calibration isn't enabled, or the draft is invalid."""


def cost_usd(input_tokens: int) -> float:
    return round(input_tokens * PRICE_USD_PER_1M_INPUT_TOKENS / 1_000_000, 8)


# --------------------------------------------------------------------------- test


@dataclass(frozen=True, slots=True)
class SampleResult:
    id: str
    decision: str
    reason: str
    expected: str | None
    expected_met: bool | None
    rules: tuple[dict[str, Any], ...]
    fired: tuple[dict[str, Any], ...]
    input_tokens: int | None
    model_called: bool


@dataclass(frozen=True, slots=True)
class HeldBack:
    position: int
    views: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DraftTestReport:
    draft_hash: str
    guard_point: str
    results: tuple[SampleResult, ...]
    input_tokens: int
    est_cost_usd: float
    calls_without_usage: int
    """Samples whose provider answer carried no usage figure: counted as unknown, not zero."""
    held_back: tuple[HeldBack, ...] = ()
    """Samples that tripped the harm vocabulary and were not sent, by position in the request's
    ``samples`` (or in the golden page) and view. Never the id or the text."""
    quarantined_not_sent: int = 0
    """Everything held back: the rows above plus golden rows the store held back as quarantined
    (those have no position here)."""
    golden: dict[str, Any] | None = None
    """For a golden-set run: ``set_id``, ``set_hash``, ``total`` at the guard point, ``offset``
    ``run``, and ``quarantined_not_sent`` (rows at that guard point held back)."""


def _expected_met(expected: str | None, decision: str) -> bool | None:
    return None if expected is None else expected == decision


class DraftTools:
    """The validate and test operations. Built beside :class:`DraftService` and over the same
    stores."""

    def __init__(
        self,
        drafts: Any,
        tenants: Any,
        catalog: Catalog,
        settings: PlatformSettings,
        evaluator: DraftEvaluator | None = None,
        golden: ScopedGoldenStores | None = None,
        calibration: Any | None = None,
    ) -> None:
        self._calibration = calibration  # a CalibrationService (M4-01)
        self._golden = golden
        self._drafts = drafts
        self._tenants = tenants
        self._catalog = catalog
        self._settings = settings
        self._evaluator = evaluator
        self._running: set[str] = set()

    async def _stored(self, scope: TenantScope) -> tuple[StoredDraft, TenantProfile]:
        draft = await self._drafts.scoped(scope).get(scope.tenant_id)
        if draft is None:
            raise NoDraftError()
        profile = await self._tenants.get(scope.tenant_id)
        if profile is None:
            raise TenantUnavailableError()
        return draft, profile

    # ------------------------------------------------------------------ M2-04

    async def validate(self, decision: AuthzDecision) -> ValidationReport:
        scope = _scope_of(decision, VALIDATE_DRAFT)
        draft, profile = await self._stored(scope)
        budget = self._settings.token_budget
        compiler = PolicyCompiler(self._catalog, profile, self._settings)
        errors = compiler.validate(draft.document, profile.attributes)
        if errors:
            return ValidationReport(
                draft.etag.strip('"'), False, tuple(_convert(errors)), token_budget=budget
            )
        compiled = compiler.compile(draft.document, profile.attributes)
        previews: dict[str, GuardPointPreview] = {}
        for name, gp in compiled.guard_points.items():
            budget_for = self._settings.question_budgets.for_guard_point(name)
            previews[name] = GuardPointPreview(
                guard_point=name,
                enabled=gp.enabled,
                question_count=len(gp.questions),
                question_budget=budget_for,
                questions=tuple(
                    _question_preview(key, gp.questions[key], gp.rules.get(key))
                    for key in gp.questions
                ),
                max_content_tokens=gp.max_content_tokens,
                content_api_tokens=gp.content_api_tokens,
                question_api_tokens=gp.question_api_tokens,
                api_tokens=gp.api_tokens,
                token_budget=budget,
                within_budget=gp.content_api_tokens <= budget,
                headroom_tokens=budget - gp.content_api_tokens,
                est_cost_usd_per_check=cost_usd(gp.api_tokens),
            )
        suggestions = None
        if self._calibration is not None:
            parsed, shape = read_bundle(draft.document)
            if parsed is not None and not shape:
                report = await self._calibration.suggestions_for(scope, draft, parsed, profile)
                suggestions = report.as_dict()
        return ValidationReport(
            draft.etag.strip('"'), True, (), previews, token_budget=budget, calibration=suggestions
        )

    # ------------------------------------------------------------------ M2-05

    async def test(self, decision: AuthzDecision, body: bytes) -> DraftTestReport:
        scope = _scope_of(decision, TEST_DRAFT)
        guard_point, samples, golden_set, offset = _parse_request(body)
        if golden_set is not None and self._golden is None:
            raise DraftInvalidError(
                [DraftError("test.golden_set_unavailable", "$.golden_set", "not enabled")]
            )
        if self._evaluator is None:
            raise EvaluatorUnavailableError()
        draft, profile = await self._stored(scope)
        golden_info: dict[str, Any] | None = None
        held_by_flag = 0
        if golden_set is not None:
            assert self._golden is not None
            store = self._golden.scoped(scope)
            info = await store.get(scope.tenant_id, golden_set)
            if info is None:
                raise GoldenSetNotFoundError()
            page_ = await store.examples(
                scope.tenant_id, golden_set, guard_point, offset=offset, limit=MAX_SAMPLES
            )
            # A quarantined row is never sent. The store doesn't return one, and this drops one
            # that still carries the flag; the tripwire below runs again on every sample.
            page = [e for e in page_.items if not e.quarantined]
            held_by_flag = page_.quarantined + len(page_.items) - len(page)
            total = page_.total
            if not page:
                raise DraftInvalidError(
                    [DraftError("test.golden_set_empty", "$.golden_set",
                                f"no examples at {guard_point!r} from offset {offset}")]
                )  # fmt: skip
            samples = [{"id": e.id, "content": e.content, "expected": e.label} for e in page]
            golden_info = {"set_id": info.set_id, "set_hash": info.set_hash, "total": total,
                           "offset": offset}  # fmt: skip
        # The tripwire runs again on EVERY sample, inline or from a golden set, with the current
        # vocabulary and independent of any stored flag, right before a request could be built
        # (decided 2026-11-17: all test traffic is ours, so the user's rule that
        # no harmful input goes to the provider applies). A sample that trips is held back and
        # reported by position and view, never by its id or text.
        sendable: list[dict[str, Any]] = []
        held: list[HeldBack] = []
        for position, sample in enumerate(samples):
            views = strings_tripwire(sample["id"], sample["content"], sample.get("tool") or "")
            if views:
                held.append(HeldBack(position, tuple(views)))
            else:
                sendable.append(sample)
        samples = sendable
        if golden_info is not None:
            golden_info["run"] = len(samples)
        parsed, shape = read_bundle(draft.document)
        assert parsed is not None and not shape  # the stored draft was validated at write
        floor_derived = self._floor_derived_keys(parsed)
        try:
            policies = self._evaluator.compile(scope.tenant_id, parsed, profile)
        except PolicyInvalidError as e:  # a catalog change since the write
            raise DraftInvalidError(_convert(e.errors)) from None
        policy = policies.get(guard_point)
        if policy is None or not policy.questions:
            raise DraftInvalidError(
                [
                    DraftError(
                        "test.no_questions",
                        "$.guard_point",
                        f"the draft asks no questions at {guard_point!r}",
                    )
                ]
            )
        if scope.tenant_id in self._running:
            raise DraftTestInProgressError()
        self._running.add(scope.tenant_id)
        try:
            results = await self._run(scope, policy, samples, floor_derived) if samples else []
        finally:
            self._running.discard(scope.tenant_id)
        known = [r.input_tokens for r in results if r.input_tokens is not None]
        tokens = sum(known)
        return DraftTestReport(
            draft_hash=draft.etag.strip('"'),
            guard_point=guard_point,
            results=tuple(results),
            input_tokens=tokens,
            est_cost_usd=cost_usd(tokens),
            calls_without_usage=sum(r.model_called and r.input_tokens is None for r in results),
            golden=golden_info,
            held_back=tuple(held),
            quarantined_not_sent=held_by_flag + len(held),
        )

    def _floor_derived_keys(self, parsed: ParsedBundle) -> frozenset[str]:
        return floor_derived_keys(self._catalog, parsed)

    async def _run(
        self,
        scope: TenantScope,
        policy: GuardPointPolicy,
        samples: list[dict[str, Any]],
        floor_derived: frozenset[str] = frozenset(),
    ) -> list[SampleResult]:
        assert self._evaluator is not None
        evaluator = self._evaluator
        gate = asyncio.Semaphore(TEST_CONCURRENCY)

        async def one(sample: dict[str, Any]) -> SampleResult:
            async with gate:
                verdict = await evaluator.evaluate(
                    scope, policy, sample["content"], sample.get("tool")
                )
            decision = str(verdict.decision)
            return SampleResult(
                id=sample["id"],
                decision=decision,
                reason=str(verdict.reason),
                expected=sample.get("expected"),
                expected_met=_expected_met(sample.get("expected"), decision),
                rules=tuple(
                    {
                        "rule": r.key,
                        "layer": r.layer,
                        "mode": r.mode,
                        "p": r.p,
                        "block_at": r.block_at,
                        "escalate_at": r.escalate_at,
                        "action": str(r.action),
                    }
                    for r in verdict.rules
                    if r.layer in TUNABLE_LAYERS and r.key not in floor_derived
                ),
                fired=tuple(_fired(f, floor_derived) for f in verdict.fired),
                input_tokens=None if verdict.usage is None else verdict.usage.total_input_tokens,
                model_called=bool(verdict.model_called),
            )

        return list(await asyncio.gather(*(one(s) for s in samples)))


def floor_derived_keys(catalog: Catalog, parsed: ParsedBundle) -> frozenset[str]:
    """The compiled keys of the tenant's rules that are the floor's own, under another key:
    ``origin`` ``fork:p__...``, or a question, true description or false description equal to a
    floor rule's after normalising case, whitespace and format characters. They are reported like
    the floor (key, action and mode when fired, never ``p``): a tenant that copies a floor rule must
    not get its probability. **Accepted residual:** a paraphrase isn't caught, and neither is the
    threshold ladder a published
    shadow rule can show; both are product-accepted (decided 2026-11-17)."""
    floor_texts: set[str] = set()
    for version in catalog.floor_versions():  # every floor, not only the extended one
        floor = catalog.floor(version)
        if floor is None:
            continue
        for rule in floor.rules:
            floor_texts.update(_question_texts(rule.question))
    derived = set()
    for rule in parsed.bundle.rules:
        texts = {
            _normalise(t)
            for t in (rule.question, rule.true_description, rule.false_description)
            if t
        }
        if rule.origin.startswith("fork:p__") or texts & floor_texts:
            derived.add(f"t__{rule.id}")
    return frozenset(derived)


TUNABLE_LAYERS = ("tenant", "pack")
"""Rules whose probability and thresholds the test endpoint shows: the tenant's own (``t__``)
and the domain packs it enabled (``d__``). A **floor** rule (``p__``) shows only what
production shows, its key, action and mode when it fires: its probability would be a
gradient to tune content just under the floor's thresholds, which protects other tenants
(``p__xtenant_probe``) and the platform."""


def _fired(fired: Any, floor_derived: frozenset[str] = frozenset()) -> dict[str, Any]:
    entry: dict[str, Any] = {"rule": fired.key, "action": str(fired.action), "mode": fired.mode}
    if fired.layer in TUNABLE_LAYERS and fired.key not in floor_derived:
        entry["p"] = fired.p
    return entry


def _normalise(text: str) -> str:
    """Case, whitespace and format characters (zero-width and the like) ignored, and NFKC."""
    kept = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    return " ".join(unicodedata.normalize("NFKC", kept).split()).casefold()


def _question_texts(question: Any) -> set[str]:
    """The normalised instructions and criteria descriptions of a catalog question."""
    texts = [getattr(question, "instructions", None)]
    criteria = getattr(question, "criteria", None)
    if criteria is not None:
        texts += [
            getattr(criteria, "true_description", None),
            getattr(criteria, "false_description", None),
        ]
    return {_normalise(t) for t in texts if isinstance(t, str) and t.strip()}


def _question_preview(key: str, question: Any, rule: Any) -> dict[str, Any]:
    preview: dict[str, Any] = {
        "key": key,
        "question": question.model_dump(mode="json", exclude_none=True),
    }
    if rule is not None:
        preview.update(
            layer=rule.layer,
            source=rule.source,
            mode=rule.mode,
            severity=rule.severity,
            block_at=rule.block_at,
            escalate_at=rule.escalate_at,
        )
    return preview


def _parse_request(body: bytes) -> tuple[str, list[dict[str, Any]], str | None, int]:
    """The test request, strictly: a JSON object with ``guard_point`` and either ``samples`` or
    ``golden_set`` (with an optional ``offset``). Every problem is reported together. Returns
    ``(guard_point, samples, golden_set, offset)``; ``samples`` is empty for a golden-set run."""
    doc, problems = parse_json_text(body)
    if problems:
        raise DraftInvalidError(_convert(problems))
    errors: list[DraftError] = []

    def bad(code: str, path: str, message: str) -> None:
        errors.append(DraftError(f"test.{code}", path, message))

    if not isinstance(doc, dict):
        raise DraftInvalidError([DraftError("test.not_object", "$", "the request is an object")])
    for extra in sorted(set(doc) - _REQUEST_FIELDS):
        bad("unknown_field", f"$.{extra}", "not a field of the request")
    guard_point = doc.get("guard_point")
    if guard_point not in GUARD_POINTS:
        bad("guard_point", "$.guard_point", f"one of {', '.join(GUARD_POINTS)}")
    golden_set = doc.get("golden_set")
    offset = doc.get("offset", 0)
    if golden_set is not None:
        if "samples" in doc:
            bad("samples_or_golden_set", "$", "send samples or a golden_set, not both")
        if not isinstance(golden_set, str) or not _GOLDEN_ID.fullmatch(golden_set):
            bad("golden_set", "$.golden_set", "a golden set id (gs_ and 16 hex digits)")
        if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
            bad("offset", "$.offset", "a whole number, 0 or more")
        if errors:
            raise DraftInvalidError(errors)
        return guard_point, [], golden_set, offset
    if "offset" in doc:
        bad("offset", "$.offset", "offset goes with golden_set")
    raw = doc.get("samples")
    samples: list[dict[str, Any]] = []
    if not isinstance(raw, list) or not 1 <= len(raw) <= MAX_SAMPLES:
        bad("samples", "$.samples", f"a list of 1 to {MAX_SAMPLES} samples")
    else:
        seen: set[str] = set()
        for i, s in enumerate(raw):
            path = f"$.samples[{i}]"
            if not isinstance(s, dict):
                bad("sample", path, "a sample is an object")
                continue
            for extra in sorted(set(s) - _SAMPLE_FIELDS):
                bad("unknown_field", f"{path}.{extra}", "not a field of a sample")
            sid, content, expected = s.get("id"), s.get("content"), s.get("expected")
            if not isinstance(sid, str) or not 1 <= len(sid) <= MAX_SAMPLE_ID_CHARS:
                bad("sample_id", f"{path}.id", f"text of 1 to {MAX_SAMPLE_ID_CHARS} characters")
            elif sid in seen:
                bad("sample_id", f"{path}.id", "ids must be unique")
            else:
                seen.add(sid)
            if not isinstance(content, str) or not content:
                bad("sample_content", f"{path}.content", "non-empty text")
            if expected is not None and expected not in EXPECTED:
                bad("sample_expected", f"{path}.expected", f"one of {', '.join(EXPECTED)}")
            tool = s.get("tool")
            if tool is not None and (
                not isinstance(tool, str) or not 1 <= len(tool) <= MAX_TOOL_CHARS
            ):
                bad("sample_tool", f"{path}.tool", f"text of 1 to {MAX_TOOL_CHARS} characters")
            samples.append(s)
    if errors:
        raise DraftInvalidError(errors)
    return guard_point, samples, None, 0
