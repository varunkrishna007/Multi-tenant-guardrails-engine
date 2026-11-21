"""The calibration job and threshold suggestions (M4-01).

For each **tenant** rule of the stored draft, the job finds the thresholds that meet the tenant's
targets on its golden sets, by the sweep of B2 (:mod:`guardrail_engine.admin.sweep`), and
the admin API shows them in ``/validate``; the tenant accepts or overrides each one.

**What is measured.** A golden example is labelled per guard point, not per rule, so a rule's
examples are the tenant's labelled examples at the guard points the rule runs on: de-duplicated by
content, leaving out quarantined rows and any content labelled both ways (the same pool the
evidence gate counts). An example labelled ``block`` is a positive for every rule at its guard
point. The probability is the rule's own ``p`` for that example.

**Stored probabilities, and when the model is called.** A probability depends on the content and
on the questions asked (and the model), not on the thresholds. So a score is stored under a
*scoring identity*: a hash of the guard point's compiled questions (floor and tenant) with the
floor version the bundle extends, and the content's hash. The job **replays** stored scores, and
calls ``decide`` (through the engine's own evaluation, with its admission control and allowances,
under the usage class ``test``) only for examples with no stored score under the draft's current
identity. Editing a threshold keeps the identity, so accepting a suggestion costs nothing; rewording
a rule or changing the floor version changes it, and those examples are scored again. Only
**tenant** rules' probabilities are stored: floor, pack and floor-derived rules' never are (they
never expose ``p``), and a tenant rule that is floor-derived gets no suggestion and no
precision gate (it is the floor's rule under another key, calibrated by the platform).

**Endpoints** (tenant routes; the scope comes from the authorizer's decision):

* ``POST /draft/calibrate`` (``guardrail_reviewer``: it spends model calls): scores up to
  :data:`MAX_NEW_SCORES` unscored examples at one guard point and stores them. A tenant has one
  run at a time. ``/validate`` itself sends nothing: its suggestions are computed from stored
  scores and say how many examples are still unscored.
* ``GET`` and ``PUT /calibration/targets``: the tenant's targets (``guardrail_admin`` to change),
  default precision 0.95 and recall 0.90, each 0.50 to 1.00 in hundredths. A change is a class A
  event: actor, before, after.
* ``POST /draft/thresholds`` (``guardrail_admin``): accept or override each rule's suggestion. It
  writes the thresholds into the draft (one ``draft.put``, with ``If-Match``) and records one
  class A ``threshold`` event per rule: the actor, accept or override, the suggestion, what was
  applied and the targets and draft it came from.

**The AC-A3 regression gate** (:meth:`CalibrationService.regression_gate`, M4-02): an enforcing
tenant rule that was also enforcing in the **active** version may not lose more than the tenant's
tolerance (``recall_tolerance``, default 2 points, 0 to 20, a setting beside the targets) of
golden-set recall against it. Recall is the share of the rule's golden positives (labelled
``block``) that it acts on, ``p`` at or above that version's ``escalate_at``: block and escalate
both count, since both keep the content from being released. Each version's recall comes from
stored scores under that version's own scoring identity and its own thresholds. Unscored examples
under either version fail closed, and the refusal says to run calibrate first: ``POST
/draft/calibrate`` takes ``"version": N`` to score a published version's document (the active
one) instead of the draft. Floor-derived rules are exempt; a rule that is new, or was in shadow in
the active version, or is gone or in shadow here, has nothing to compare and isn't gated. The
first publish has no active version and passes, and its record says so.

**The R1 precision gate** (:meth:`CalibrationService.precision_gate`): an enforcing tenant rule's
``block_at`` must meet the tenant's precision target on its golden set, computed as in B2, from
the stored scores of **every** example in its pool. A rule with unscored examples, or with
nothing predicted at its ``block_at``, fails with the numbers. Every result, a pass too, records
the targets, the draft's bundle hash and the floor version it used.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from guardrail_engine.admin.calibration_store import (
    TERMINAL_ATTEMPTS,
    CalibrationAuditEvent,
    ScopedCalibrationStores,
)
from guardrail_engine.admin.drafts import StoredDraft
from guardrail_engine.admin.evidence import GateFailure
from guardrail_engine.admin.golden import ScopedGoldenStores, content_key
from guardrail_engine.admin.service import (
    DraftError,
    DraftInvalidError,
    DraftService,
    DraftServiceError,
    NoDraftError,
    PreconditionRequiredError,
    TenantUnavailableError,
    _convert,
    _if_match_ok,
    _scope_of,
)
from guardrail_engine.admin.sweep import (
    DEFAULT_PRECISION,
    DEFAULT_RECALL,
    Suggestion,
    TargetError,
    Targets,
    precision_at,
    sweep,
)
from guardrail_engine.admin.tools import (
    DraftEvaluator,
    EvaluatorUnavailableError,
    cost_usd,
    floor_derived_keys,
)
from guardrail_engine.admin.vocabulary import strings_tripwire
from guardrail_engine.authz.authorizer import AuthzDecision
from guardrail_engine.authz.model import Principal
from guardrail_engine.guard.tenants import TenantProfile, ToolInfo
from guardrail_engine.policy.canonical import sha256_of
from guardrail_engine.policy.catalog import Catalog, PlatformSettings
from guardrail_engine.policy.compiler import PolicyCompiler
from guardrail_engine.policy.document import ParsedBundle, read_bundle
from guardrail_engine.policy.errors import PolicyInvalidError
from guardrail_engine.policy.json_document import parse_json_text
from guardrail_engine.policy.schema import GUARD_POINTS
from guardrail_engine.tenant_scope import TenantScope

_T = "/v1/tenants/{tid}/guardrails"
READ_TARGETS = ("GET", f"{_T}/calibration/targets")
UPDATE_TARGETS = ("PUT", f"{_T}/calibration/targets")
CALIBRATE_DRAFT = ("POST", f"{_T}/draft/calibrate")
DECIDE_THRESHOLDS = ("POST", f"{_T}/draft/thresholds")

MAX_NEW_SCORES = 50
"""Examples one ``calibrate`` request may score (as many as a test run may send)."""
CONCURRENCY = 4
MAX_REASON_CHARS = 200
_GOLDEN_PAGE = 1000
_RULE_ID = re.compile(r"[A-Za-z0-9_.-]{1,64}")


class CalibrationInProgressError(DraftServiceError):
    """The tenant already has a calibration run going (HTTP 429)."""


class StaleSuggestionError(DraftServiceError):
    """The draft changed since the suggestion was shown (HTTP 409)."""


def content_hash(content: str) -> str:
    """The key of an example's stored scores: the hash of its normalised content (the same
    notion of "the same example" the evidence gate counts by)."""
    import hashlib

    return "sha256:" + hashlib.sha256(content_key(content).encode("utf-8")).hexdigest()


def floor_refs(parsed: ParsedBundle) -> tuple[str, ...]:
    """The floor versions the bundle extends (``platform/floor@2``)."""
    return tuple(sorted(e for e in parsed.bundle.extends if e.startswith("platform/floor@")))


RENDER_VERSION = "1"
"""Bump this when what the model is shown for a given content changes without any of the inputs
below changing (the render format, the redaction pipeline's defaults): every stored score is then
out of date."""


def scoring_hash(
    guard_point: str,
    questions: Mapping[str, Any],
    floor: Sequence[str],
    *,
    deterministic: Mapping[str, Any] | None = None,
    max_content_tokens: int | None = None,
) -> str:
    """The scoring identity of one guard point: a stored score (or a stored outcome) is valid
    exactly while everything that decides what the model is asked about an example is the same:
    the questions (floor and tenant) and the floor version; the effective **max content tokens**
    (content over it never reaches the model); the bundle's **deterministic** section (the PII
    detection and action and the deny patterns, which redact or block before the model); and the
    render version. Thresholds are not part of it."""
    return sha256_of(
        {
            "guard_point": guard_point,
            "floor": sorted(floor),
            "questions": {
                key: question.model_dump(mode="json", exclude_none=True)
                for key, question in sorted(questions.items())
            },
            "max_content_tokens": max_content_tokens,
            "deterministic": dict(deterministic or {}),
            "render": RENDER_VERSION,
        }
    )


def deterministic_of(parsed: ParsedBundle) -> dict[str, Any]:
    """The bundle's effective deterministic section, as JSON."""
    return parsed.bundle.deterministic.model_dump(mode="json")


def terminal_cause(attempts: Mapping[str, int] | None) -> str | None:
    """The cause that makes an example leave the pool for good, from its recorded attempts: a
    deterministic block or a too-large content once, a provider refusal twice."""
    for cause, needed in TERMINAL_ATTEMPTS.items():
        if (attempts or {}).get(cause, 0) >= needed:
            return cause
    return None


def outcome_of(verdict: Any) -> str:
    """What a verdict that gave no probabilities says about the example. ``deterministic``: a
    tenant deny pattern or a PII block stopped it before the model. ``too_large``: over the guard
    point's content budget. ``refused``: the provider's safety refusal. Anything else (a model
    failure, admission, the engine closing) is ``failed``, which is retried."""
    reason = str(getattr(verdict, "reason", ""))
    if reason == "deterministic":
        return "deterministic"
    if reason == "content_too_large":
        return "too_large"
    if reason == "provider_safety":
        return "refused"
    return "failed"


@dataclass(frozen=True, slots=True)
class PoolItem:
    hash: str
    content: str
    label: str

    @property
    def positive(self) -> bool:
        return self.label == "block"


@dataclass(frozen=True, slots=True)
class ItemState:
    """One example of a rule's pool, as stored scores see it."""

    positive: bool
    p: float | None = None
    """The rule's stored probability; None when it has none."""
    cause: str | None = None
    """Why it has none and never will under this identity: ``deterministic`` (a tenant deny
    pattern or PII block stops it before the model, so the content is blocked anyway),
    ``too_large``, ``refused`` or ``held``; None for a scored example or an unscored one."""


@dataclass
class PoolStatus:
    """What stored scores say about one rule's pool (a rule's examples at its guard points)."""

    pairs: list[tuple[float, bool]] = field(default_factory=list)
    """``(p, labelled block)`` for each scored example."""
    unscored: int = 0
    excluded: dict[str, int] = field(default_factory=dict)
    """Out of the pool, by cause: the golden pool's own (``both_labels``, ``quarantined``) and
    the unscorable ones (``deterministic``, ``too_large``, ``refused``, ``held``)."""
    items: dict[str, ItemState] = field(default_factory=dict)
    """Every example of the pool that wasn't left out by the golden pool itself, keyed by
    guard point and content hash, for comparing two versions example by example."""

    def exclude(self, cause: str, n: int = 1) -> None:
        if n:
            self.excluded[cause] = self.excluded.get(cause, 0) + n

    @property
    def positives(self) -> int:
        return sum(1 for _, positive in self.pairs if positive)

    @property
    def negatives(self) -> int:
        return len(self.pairs) - self.positives

    @property
    def excluded_text(self) -> str:
        """``deterministic:2,held:1``, for a record or a message (counts, never content)."""
        return ",".join(f"{c}:{n}" for c, n in sorted(self.excluded.items()))

    @property
    def composition(self) -> str:
        """The pool, for a record: ``n=48 pos=24 neg=24 excl=deterministic:2,both_labels:1``."""
        text = f"n={len(self.pairs)} pos={self.positives} neg={self.negatives}"
        return text + (f" excl={self.excluded_text}" if self.excluded else "")


@dataclass(frozen=True, slots=True)
class TargetsView:
    targets: Targets
    is_default: bool

    def as_dict(self) -> dict[str, Any]:
        return {**self.targets.as_dict(), "is_default": self.is_default}


@dataclass(frozen=True, slots=True)
class RuleSuggestion:
    """The suggestion for one tenant rule, with what it was computed from."""

    rule: str
    key: str
    guard_points: tuple[str, ...]
    suggestion: Suggestion
    scored: int
    """Pool examples at the rule's guard points with a stored score."""
    unscored: int
    """Pool examples without one: ``calibrate`` scores them."""
    current: dict[str, float | None]
    excluded: dict[str, int] = field(default_factory=dict)
    """Examples left out of the rule's pool, by cause, never by content: ``deterministic``,
    ``too_large``, ``refused`` (see :func:`terminal_cause`) and ``held`` (the harm tripwire)."""

    def as_dict(self) -> dict[str, Any]:
        s = self.suggestion
        return {
            "rule": self.rule,
            "key": self.key,
            "guard_points": list(self.guard_points),
            "available": s.available,
            "block_at": s.block_at,
            "escalate_at": s.escalate_at,
            "band_empty": s.band_empty,
            "precision": s.precision,
            "recall": s.recall,
            "examples": s.examples,
            "positives": s.positives,
            "reason": s.reason,
            "scored": self.scored,
            "unscored": self.unscored,
            "excluded": dict(self.excluded),
            "current": self.current,
        }


@dataclass(frozen=True, slots=True)
class SuggestionReport:
    """Everything a set of suggestions was computed from (it goes into /validate and into the
    audit): the targets, the draft and the floor."""

    targets: TargetsView
    draft_hash: str
    bundle_hash: str
    floor: tuple[str, ...]
    rules: tuple[RuleSuggestion, ...]

    @property
    def digest(self) -> str:
        """What /validate shows, as a hash: the accept request names it, so that it can only
        apply the suggestion the tenant saw. It covers the draft, the targets and each
        rule's suggestion with the counts behind it."""
        return sha256_of(
            {
                "draft_hash": self.draft_hash,
                "targets": self.targets.as_dict(),
                "rules": [r.as_dict() for r in self.rules],
            }
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "digest": self.digest,
            "targets": self.targets.as_dict(),
            "draft_hash": self.draft_hash,
            "bundle_hash": self.bundle_hash,
            "floor": list(self.floor),
            "rules": [r.as_dict() for r in self.rules],
        }


@dataclass(frozen=True, slots=True)
class CalibrationRunReport:
    guard_point: str
    pool: int
    """Distinct labelled examples at the guard point that may be sent."""
    already_scored: int
    scored_now: int
    not_scored: int
    """Sent, but the engine gave no probability this time (a block before the model, a refusal,
    a model failure): ``terminal_now`` of them leave the pool for good, ``failed_now`` are
    retried later, behind examples tried less often."""
    unscored_remaining: int
    """Examples still to try: never tried first, then the ones that failed before."""
    held_back: int
    """Not sent: the harm vocabulary tripwire (the user's rule). They are out of the pool."""
    input_tokens: int
    est_cost_usd: float
    calls_without_usage: int
    scoring: str
    targets: dict[str, Any] = field(default_factory=dict)
    terminal_now: dict[str, int] = field(default_factory=dict)
    failed_now: int = 0
    excluded: dict[str, int] = field(default_factory=dict)
    """Everything now out of the pool at this guard point, by cause (``held`` is the harm
    tripwire); counts only, never content."""
    version: int | None = None
    """The published version that was scored, or None for the draft."""


def _fail(code: str, path: str, message: str) -> DraftInvalidError:
    return DraftInvalidError([DraftError(code, path, message)])


def _targets_view(stored: Targets | None) -> TargetsView:
    return TargetsView(stored or Targets(DEFAULT_PRECISION, DEFAULT_RECALL), stored is None)


class CalibrationService:
    """The calibration job, the suggestions, the targets and the precision gate. Built beside
    the draft tools over the same stores."""

    def __init__(
        self,
        drafts: Any,
        tenants: Any,
        catalog: Catalog,
        settings: PlatformSettings,
        golden: ScopedGoldenStores,
        store: ScopedCalibrationStores,
        draft_service: DraftService,
        evaluator: DraftEvaluator | None = None,
        clock: Any = None,
        concurrency: int = CONCURRENCY,
        lifecycle: Any | None = None,
    ) -> None:
        import time
        from datetime import UTC, datetime

        self._drafts = drafts
        self._tenants = tenants
        self._catalog = catalog
        self._settings = settings
        self._golden = golden
        self._store = store
        self._service = draft_service
        self._evaluator = evaluator
        self._clock = clock or (lambda: datetime.fromtimestamp(time.time(), UTC))
        self._lifecycle = lifecycle  # ScopedLifecycleStores: the documents of published versions
        self._concurrency = max(1, concurrency)
        self._running: set[str] = set()

    # ------------------------------------------------------------------ targets

    async def targets_for(self, scope: TenantScope) -> TargetsView:
        return _targets_view(await self._store.scoped(scope).get_targets(scope.tenant_id))

    async def read_targets(self, decision: AuthzDecision) -> TargetsView:
        return await self.targets_for(_scope_of(decision, READ_TARGETS))

    async def set_targets(
        self, decision: AuthzDecision, principal: Principal, body: bytes
    ) -> TargetsView:
        scope = _scope_of(decision, UPDATE_TARGETS)
        doc, problems = parse_json_text(body)
        if problems:
            raise DraftInvalidError(_convert(problems))
        names = {"block_precision", "escalate_recall", "recall_tolerance"}
        if not isinstance(doc, dict) or not doc or set(doc) - names:
            raise _fail(
                "calibration.targets",
                "$",
                "an object with block_precision, escalate_recall and/or recall_tolerance",
            )
        before = await self.targets_for(scope)
        try:
            after = Targets(
                doc.get("block_precision", before.targets.block_precision),
                doc.get("escalate_recall", before.targets.escalate_recall),
                doc.get("recall_tolerance", before.targets.recall_tolerance),
            )
        except TargetError as e:
            raise _fail("calibration.targets", "$", str(e)) from None
        event = CalibrationAuditEvent(
            at=self._clock(),
            actor=principal.actor,
            tenant_id=scope.tenant_id,
            kind="targets",
            detail={
                "before": before.targets.as_dict(),
                "before_is_default": before.is_default,
                "after": after.as_dict(),
            },
            cross_tenant=decision.cross_tenant,
            operator=principal.platform_operator,
        )
        await self._store.scoped(scope).set_targets(scope.tenant_id, after, event)
        return TargetsView(after, False)

    # ------------------------------------------------------------------ the pool and scores

    async def pool(self, scope: TenantScope, guard_point: str) -> list[PoolItem]:
        """The tenant's labelled examples at ``guard_point`` that may be sent: over all its
        golden sets, de-duplicated by normalised content, leaving out quarantined rows and
        content labelled both ways."""
        return (await self.pool_view(scope, guard_point))[0]

    async def pool_view(
        self, scope: TenantScope, guard_point: str
    ) -> tuple[list[PoolItem], int, int]:
        """:meth:`pool`, with how many contents it left out for carrying both labels and how
        many rows for being quarantined (the records say so)."""
        store = self._golden.scoped(scope)
        first: dict[str, PoolItem] = {}
        labels: dict[str, set[str]] = {}
        quarantined = 0
        for info in await store.list(scope.tenant_id):
            offset = 0
            while True:
                page = await store.examples(
                    scope.tenant_id, info.set_id, guard_point, offset=offset, limit=_GOLDEN_PAGE
                )
                quarantined += page.quarantined if offset == 0 else 0
                for e in page.items:
                    if e.quarantined:
                        continue
                    h = content_hash(e.content)
                    labels.setdefault(h, set()).add(e.label)
                    first.setdefault(h, PoolItem(h, e.content, e.label))
                offset += len(page.items)
                if not page.items or offset >= page.total:
                    break
        kept = [item for h, item in first.items() if len(labels[h]) == 1]
        return kept, len(first) - len(kept), quarantined

    def _compiled(self, parsed: ParsedBundle, profile: TenantProfile) -> Any:
        return PolicyCompiler(self._catalog, profile, self._settings).compile(
            parsed, profile.attributes
        )

    async def _stored(self, scope: TenantScope) -> tuple[StoredDraft, TenantProfile]:
        draft = await self._drafts.scoped(scope).get(scope.tenant_id)
        if draft is None:
            raise NoDraftError()
        profile = await self._tenants.get(scope.tenant_id)
        if profile is None:
            raise TenantUnavailableError()
        return draft, profile

    # ------------------------------------------------------------------ the job

    async def calibrate(self, decision: AuthzDecision, body: bytes) -> CalibrationRunReport:
        """Score the draft's unscored golden examples at one guard point (at most
        :data:`MAX_NEW_SCORES`), storing each tenant rule's probability. An example that can
        never be scored (a block before the model, too large, refused twice) is recorded and
        leaves the pool; one that failed is retried behind the ones tried less often. With
        ``version``, the document of that published version is scored instead of the draft (the
        regression gate compares a draft with the active version's scores)."""
        scope = _scope_of(decision, CALIBRATE_DRAFT)
        guard_point, version = _parse_calibrate(body)
        if self._evaluator is None:
            raise EvaluatorUnavailableError()
        if version is None:
            draft, profile = await self._stored(scope)
            document: Any = draft.document
        else:
            profile = await self._tenants.get(scope.tenant_id)
            if profile is None:
                raise TenantUnavailableError()
            document = (
                None
                if self._lifecycle is None
                else await self._lifecycle.scoped(scope).document(scope.tenant_id, version)
            )
            if document is None:
                raise _fail("calibrate.version", "$.version", "the tenant has no such version")
        parsed, shape = read_bundle(document)
        if parsed is None or shape:  # a draft was validated at write; a version at publish
            raise DraftInvalidError(_convert(shape))
        derived = floor_derived_keys(self._catalog, parsed)
        if version is not None:
            # A published version is scored with the same stub registry the gate measures it
            # with: one that names a tool the tenant has since lost can still be scored.
            profile = self._measuring_profile(parsed, profile)
        try:
            policies = self._evaluator.compile(scope.tenant_id, parsed, profile)
        except PolicyInvalidError as e:
            raise DraftInvalidError(_convert(e.errors)) from None
        policy = policies.get(guard_point)
        tenant_keys = {
            f"t__{r.id}"
            for r in parsed.bundle.rules
            if guard_point in r.guard_points and f"t__{r.id}" not in derived
        }
        if policy is None or not tenant_keys & set(policy.questions):
            raise _fail(
                "calibrate.no_rules",
                "$.guard_point",
                f"the {'draft' if version is None else f'version {version}'} has no tenant rule "
                f"of its own at {guard_point!r} to calibrate",
            )
        scoring = scoring_hash(
            guard_point, policy.questions, floor_refs(parsed),
            deterministic=deterministic_of(parsed), max_content_tokens=policy.max_content_tokens,
        )  # fmt: skip
        if scope.tenant_id in self._running:
            raise CalibrationInProgressError()
        self._running.add(scope.tenant_id)
        try:
            return await self._score(
                scope,
                policy,
                guard_point,
                scoring,
                tenant_keys,
                await self.targets_for(scope),
                version,
            )
        finally:
            self._running.discard(scope.tenant_id)

    async def _score(
        self,
        scope: TenantScope,
        policy: Any,
        guard_point: str,
        scoring: str,
        tenant_keys: set[str],
        targets: TargetsView,
        version: int | None = None,
    ) -> CalibrationRunReport:
        assert self._evaluator is not None
        evaluator = self._evaluator
        store = self._store.scoped(scope)
        pool = await self.pool(scope, guard_point)
        hashes = [item.hash for item in pool]
        have = await store.get_scores(scope.tenant_id, scoring, guard_point, hashes)
        attempts = await store.get_outcomes(scope.tenant_id, scoring, guard_point, hashes)
        excluded: dict[str, int] = {}
        pending: list[PoolItem] = []
        for item in pool:
            # The harm tripwire runs on every example right before a request could be built,
            # with the current vocabulary (the user's rule: nothing harmful goes to the
            # provider). A held example is out of the pool.
            if strings_tripwire(item.content):
                excluded["held"] = excluded.get("held", 0) + 1
            elif item.hash in have:
                continue
            elif (cause := terminal_cause(attempts.get(item.hash))) is not None:
                excluded[cause] = excluded.get(cause, 0) + 1
            else:
                pending.append(item)
        # Never-tried examples first, then the ones that failed before, fewest attempts first
        # (stable: the pool's own order within a count), so a run always makes progress past
        # whatever keeps failing.
        pending.sort(key=lambda i: sum(attempts.get(i.hash, {}).values()))
        batch = pending[:MAX_NEW_SCORES]
        gate = asyncio.Semaphore(self._concurrency)

        async def one(item: PoolItem) -> tuple[PoolItem, Any]:
            async with gate:
                verdict = await evaluator.evaluate(scope, policy, item.content)
            return item, verdict

        results = list(await asyncio.gather(*(one(i) for i in batch))) if batch else []
        new: dict[str, dict[str, float]] = {}
        outcomes: dict[str, str] = {}
        tokens = no_usage = 0
        needed = tenant_keys & set(policy.questions)
        for item, verdict in results:
            usage = getattr(verdict, "usage", None)
            if usage is not None:
                tokens += usage.total_input_tokens
            elif getattr(verdict, "model_called", False):
                no_usage += 1
            by_rule = {
                r.key: r.p
                for r in verdict.rules
                if r.layer == "tenant" and r.key in tenant_keys and r.p is not None
            }
            if verdict.model_called and by_rule and set(by_rule) == needed:
                new[item.hash] = by_rule
            else:
                outcomes[item.hash] = outcome_of(verdict)
        await store.put_scores(scope.tenant_id, scoring, guard_point, new)
        await store.put_outcomes(scope.tenant_id, scoring, guard_point, outcomes)
        terminal_now: dict[str, int] = {}
        failed_now = 0
        for h, cause in outcomes.items():
            counts = dict(attempts.get(h, {}))
            counts[cause] = counts.get(cause, 0) + 1
            if (final := terminal_cause(counts)) is not None:
                terminal_now[final] = terminal_now.get(final, 0) + 1
                excluded[final] = excluded.get(final, 0) + 1
            else:
                failed_now += 1
        return CalibrationRunReport(
            guard_point=guard_point,
            pool=len(pool),
            already_scored=len(have),
            scored_now=len(new),
            not_scored=len(outcomes),
            unscored_remaining=len(pending) - len(new) - sum(terminal_now.values()),
            held_back=excluded.get("held", 0),
            input_tokens=tokens,
            est_cost_usd=cost_usd(tokens),
            calls_without_usage=no_usage,
            scoring=scoring,
            targets=targets.as_dict(),
            terminal_now=terminal_now,
            failed_now=failed_now,
            excluded=excluded,
            version=version,
        )

    # ------------------------------------------------------------------ suggestions

    async def suggestions_for(
        self,
        scope: TenantScope,
        draft: StoredDraft,
        parsed: ParsedBundle,
        profile: TenantProfile,
    ) -> SuggestionReport:
        """The B2 suggestion for each of the draft's tenant rules, from **stored** scores:
        nothing is sent to a model. A floor-derived rule has none."""
        targets = await self.targets_for(scope)
        compiled = self._compiled(parsed, profile)
        derived = floor_derived_keys(self._catalog, parsed)
        floor = floor_refs(parsed)
        rules: list[RuleSuggestion] = []
        for rule in parsed.bundle.rules:
            key = f"t__{rule.id}"
            if key in derived:
                continue
            rules.append(
                await self._for_rule(scope, compiled, parsed, floor, rule, key, targets.targets)
            )
        return SuggestionReport(
            targets, draft.etag.strip('"'), compiled.bundle_hash, floor, tuple(rules)
        )

    async def _scores_for(
        self,
        scope: TenantScope,
        compiled: Any,
        parsed: ParsedBundle,
        floor: Sequence[str],
        rule: Any,
        key: str,
    ) -> PoolStatus:
        """What stored scores say about the rule's pool, over the guard points it runs on:
        the ``(p, positive)`` pairs, how many examples are unscored (``calibrate`` can fix
        that), and how many are out of the pool for good, by cause."""
        store = self._store.scoped(scope)
        status = PoolStatus()
        for gp in sorted(rule.guard_points):
            cgp = compiled.guard_points.get(gp)
            if cgp is None or key not in cgp.questions:
                continue
            pool, both_labels, quarantined = await self.pool_view(scope, gp)
            status.exclude("both_labels", both_labels)
            status.exclude("quarantined", quarantined)
            hashes = [i.hash for i in pool]
            scoring = scoring_hash(
                gp, cgp.questions, floor,
                deterministic=deterministic_of(parsed), max_content_tokens=cgp.max_content_tokens,
            )  # fmt: skip
            have = await store.get_scores(scope.tenant_id, scoring, gp, hashes)
            attempts = await store.get_outcomes(scope.tenant_id, scoring, gp, hashes)
            for item in pool:
                by_rule = have.get(item.hash)
                at = f"{gp}:{item.hash}"
                if strings_tripwire(item.content):
                    status.exclude("held")
                    status.items[at] = ItemState(item.positive, cause="held")
                elif by_rule is not None and key in by_rule:
                    status.pairs.append((by_rule[key], item.positive))
                    status.items[at] = ItemState(item.positive, p=by_rule[key])
                elif (cause := terminal_cause(attempts.get(item.hash))) is not None:
                    status.exclude(cause)
                    status.items[at] = ItemState(item.positive, cause=cause)
                else:
                    status.unscored += 1
                    status.items[at] = ItemState(item.positive)
        return status

    async def _for_rule(
        self,
        scope: TenantScope,
        compiled: Any,
        parsed: ParsedBundle,
        floor: Sequence[str],
        rule: Any,
        key: str,
        targets: Targets,
    ) -> RuleSuggestion:
        status = await self._scores_for(scope, compiled, parsed, floor, rule, key)
        cr = next(
            (
                cgp.rules[key]
                for gp in sorted(rule.guard_points)
                if (cgp := compiled.guard_points.get(gp)) is not None and key in cgp.rules
            ),
            None,
        )
        current = {
            "block_at": None if cr is None else cr.block_at,
            "escalate_at": None if cr is None else cr.escalate_at,
        }
        cap = None if cr is None else cr.max_action
        return RuleSuggestion(
            rule.id, key, tuple(sorted(rule.guard_points)),
            sweep(status.pairs, targets, max_action=cap),
            len(status.pairs), status.unscored, current, dict(status.excluded),
        )  # fmt: skip

    async def decide_thresholds(
        self, decision: AuthzDecision, principal: Principal, body: bytes, if_match: str | None
    ) -> dict[str, Any]:
        """Accept or override the suggestion for each named rule, in one draft write."""
        scope = _scope_of(decision, DECIDE_THRESHOLDS)
        digest, wanted = _parse_decisions(body)
        draft, profile = await self._stored(scope)
        if if_match is None:
            raise PreconditionRequiredError()
        if not _if_match_ok(if_match, draft.etag):
            raise StaleSuggestionError("the draft changed since the suggestions were shown")
        parsed, shape = read_bundle(draft.document)
        assert parsed is not None and not shape
        report = await self.suggestions_for(scope, draft, parsed, profile)
        accepting = any(w["action"] == "accept" for w in wanted.values())
        if accepting and digest is None:
            raise _fail(
                "thresholds.digest",
                "$.digest",
                "accepting names the digest of the suggestions /validate returned",
            )
        if accepting and digest != report.digest:
            raise StaleSuggestionError(
                "the suggestions are not the ones you were shown (the draft, the scores or the "
                "targets changed); validate again"
            )
        by_id = {r.rule: r for r in report.rules}
        document = json.loads(draft.document)
        rules_json = {r.get("id"): r for r in document.get("rules", []) if isinstance(r, dict)}
        events: list[dict[str, Any]] = []
        errors: list[DraftError] = []
        for rule_id, want in wanted.items():
            path = f"$.rules.{rule_id}"
            found = by_id.get(rule_id)
            if found is None or rule_id not in rules_json:
                errors.append(
                    DraftError(
                        "thresholds.unknown_rule", path,
                        "not a tenant rule of the draft with its own thresholds",
                    )
                )  # fmt: skip
                continue
            suggestion = found.suggestion
            if want["action"] == "accept":
                if not suggestion.available:
                    errors.append(
                        DraftError(
                            "thresholds.no_suggestion", path,
                            f"no suggestion to accept ({suggestion.reason})",
                        )
                    )  # fmt: skip
                    continue
                block = suggestion.block_at
                escalate = suggestion.escalate_at
                if suggestion.escalate_only:  # a capped rule: only escalate_at is tuned
                    block = found.current.get("block_at")
                if escalate is None:  # recall unreachable: keep the rule's own escalate_at
                    escalate = found.current.get("escalate_at")
            else:
                block, escalate = want["block_at"], want["escalate_at"]
            if block is None or escalate is None or not 0.01 <= escalate < block <= 0.99:
                errors.append(
                    DraftError(
                        "thresholds.invalid", path,
                        "need 0.01 <= escalate_at < block_at <= 0.99",
                    )
                )  # fmt: skip
                continue
            rules_json[rule_id]["block_at"] = round(block, 2)
            rules_json[rule_id]["escalate_at"] = round(escalate, 2)
            events.append(
                {
                    "rule": rule_id,
                    "action": want["action"],
                    "reason": want.get("reason"),
                    "suggested": _suggested(found),
                    "previous": found.current,
                    "applied": {"block_at": round(block, 2), "escalate_at": round(escalate, 2)},
                }
            )
        if errors:
            raise DraftInvalidError(errors)
        # The decisions are written in the draft write's own audit event (action
        # ``draft.thresholds``), so they commit together or not at all.
        detail = {
            "decisions": events,
            "digest": report.digest,
            "targets": report.targets.as_dict(),
            "bundle_hash": report.bundle_hash,
            "floor": list(report.floor),
        }
        saved = await self._service.write_document(
            scope, decision, principal, "draft.thresholds",
            json.dumps(document, sort_keys=True).encode("utf-8"), if_match, detail,
        )  # fmt: skip
        return {
            "draft_hash": saved.etag.strip('"'),
            "decisions": events,
            "targets": detail["targets"],
            "floor": detail["floor"],
        }

    # ------------------------------------------------------------------ the R1 precision gate

    async def precision_gate(
        self, scope: TenantScope, document: dict[str, Any]
    ) -> tuple[list[GateFailure], str]:
        """The precision part of the evidence gate: for each enforcing tenant rule of
        ``document``, its ``block_at`` must meet the tenant's precision target on the stored
        scores of its whole pool. Returns the failures and a one-line record of what was used
        (targets, bundle hash, floor), which the publish event carries."""
        profile = await self._tenants.get(scope.tenant_id)
        if profile is None:
            raise TenantUnavailableError()
        parsed, shape = read_bundle(document)
        if parsed is None or shape:
            return [], ""  # the compiler reports it
        targets = (await self.targets_for(scope)).targets
        compiled = self._compiled(parsed, profile)
        derived = floor_derived_keys(self._catalog, parsed)
        floor = floor_refs(parsed)
        failures: list[GateFailure] = []
        parts: list[str] = []
        for rule in parsed.bundle.rules:
            key = f"t__{rule.id}"
            if rule.mode != "enforce" or key in derived:
                continue
            status = await self._scores_for(scope, compiled, parsed, floor, rule, key)
            pairs, unscored = status.pairs, status.unscored
            cr = next(
                (
                    cgp.rules[key]
                    for gp in sorted(rule.guard_points)
                    if (cgp := compiled.guard_points.get(gp)) is not None and key in cgp.rules
                ),
                None,
            )
            block_at = None if cr is None else cr.block_at
            if cr is not None and cr.max_action == "escalate":
                # A rule that can only escalate (a fork of a capped platform rule) never
                # blocks, so a precision gate on its block_at measures nothing it does.
                parts.append(f"{rule.id} escalate-only, no precision gate")
                continue
            if unscored or not pairs or block_at is None:
                failures.append(
                    GateFailure(
                        rule.id,
                        "precision",
                        f"{unscored} of the rule's golden examples have no stored score for the "
                        "rule as worded now; run POST /draft/calibrate for each of its guard "
                        "points before enforcing" + _left_out(status)
                        if unscored or not pairs
                        else "the rule has no block threshold",
                    )
                )
                continue
            point = precision_at(pairs, block_at)
            if not (point.precision is not None and point.precision >= targets.block_precision):
                shown = (
                    "nothing is predicted"
                    if point.precision is None
                    else (f"precision {point.precision:.3f} ({point.tp} of {point.predicted})")
                )
                failures.append(
                    GateFailure(
                        rule.id,
                        "precision",
                        f"at block_at {block_at}: {shown}, below the target "
                        f"{targets.block_precision:.2f} on {len(pairs)} golden examples"
                        + _left_out(status),
                    )
                )
            else:
                left = f" excl={status.excluded_text}" if status.excluded else ""
                parts.append(f"{rule.id} {point.precision:.2f}@{block_at} n={len(pairs)}{left}")
        record = (
            f"precision gate: targets p>={targets.block_precision:.2f} "
            f"r>={targets.escalate_recall:.2f}; "
            f"bundle {compiled.bundle_hash[:19]}; floor {','.join(floor) or '-'}; "
            + ("; ".join(parts) if parts else "no enforcing tenant rule")
        )
        return failures, record

    # ------------------------------------------------------------------ the AC-A3 regression gate

    def _compiled_for_measuring(self, parsed: ParsedBundle, profile: TenantProfile) -> Any:
        """Compile a published version to measure it, with the tenant's profile **plus a stub
        for every tool its allow-lists name**. Recall doesn't depend on the tool
        allow-list, and a tenant can unregister a tool (a delete, a held edit before the fix)
        without any publish: a version that names a tool the registry no longer has must still
        be measurable. Everything else compiles as it does for a check."""
        return self._compiled(parsed, self._measuring_profile(parsed, profile))

    @staticmethod
    def _measuring_profile(parsed: ParsedBundle, profile: TenantProfile) -> TenantProfile:
        """``profile`` with a stub entry for every tool the bundle's allow-lists name that the
        registry lacks. Unchanged if a stub would be refused (the compile then says why)."""
        named = {
            tool
            for config in parsed.bundle.guard_points.values()
            for tool in (config.tool_allowlist or ())
        }
        missing = sorted(named - set(profile.tools))
        if missing:
            # A stub the profile refuses: the compile below says why.
            with contextlib.suppress(ValueError):
                profile = TenantProfile.build(
                    profile.attributes,
                    profile.domain,
                    [*profile.tools.values(), *(ToolInfo(name) for name in missing)],
                    slug=profile.slug,
                    require_two_person=profile.require_two_person,
                )
        return profile

    async def regression_gate(
        self,
        scope: TenantScope,
        document: dict[str, Any],
        active_version: int | None,
        active_document: dict[str, Any] | None,
    ) -> tuple[list[GateFailure], str]:
        """The regression part of the evidence gate (M4-02): each enforcing tenant rule of
        ``document`` that was also enforcing in the active version may lose at most the tenant's
        tolerance of golden-set recall against it. Returns the failures and a one-line record.

        **Failing to measure the active version fails closed**, except for one case: it extends
        a floor that is now below the platform's minimum or no longer released (the platform
        moved it; there is nothing to measure with, and this publish is probably the fix), and
        the record says so."""
        if active_document is None or active_version is None:
            return [], "regression gate: first publish, no active version to compare"
        profile = await self._tenants.get(scope.tenant_id)
        if profile is None:
            raise TenantUnavailableError()
        new, shape = read_bundle(document)
        old, old_shape = read_bundle(active_document)
        if new is None or shape:
            return [], ""  # the compiler reports it
        old_rules = {r.id: r for r in old.bundle.rules} if old is not None else {}
        derived_new = floor_derived_keys(self._catalog, new)
        candidates = [
            r
            for r in new.bundle.rules
            if r.mode == "enforce"
            and f"t__{r.id}" not in derived_new
            and (was := old_rules.get(r.id)) is not None
            and was.mode == "enforce"
        ]
        if old is None or old_shape:
            return _cannot_measure(candidates, active_version, "it can't be read")
        try:
            compiled_old = self._compiled_for_measuring(old, profile)
        except PolicyInvalidError as e:
            codes = {str(err.code.value) for err in e.errors}
            if codes <= FLOOR_MOVED:
                return [], (
                    f"regression gate: v{active_version} extends a floor that is now below the "
                    "minimum or unreleased, not compared"
                )
            return _cannot_measure(candidates, active_version, ", ".join(sorted(codes)[:4]))
        compiled_new = self._compiled(new, profile)
        tolerance = (await self.targets_for(scope)).targets.recall_tolerance
        derived_old = floor_derived_keys(self._catalog, old)
        floor_new, floor_old = floor_refs(new), floor_refs(old)
        failures: list[GateFailure] = []
        parts: list[str] = []
        for rule in candidates:
            key = f"t__{rule.id}"
            was = old_rules[rule.id]
            if key in derived_old:
                continue
            new_status = await self._scores_for(scope, compiled_new, new, floor_new, rule, key)
            old_status = await self._scores_for(scope, compiled_old, old, floor_old, was, key)
            missing = []
            if old_status.unscored or not old_status.pairs:
                missing.append(
                    f"{old_status.unscored or 'all'} golden examples have no stored score under "
                    f"the active version v{active_version}'s wording: POST /draft/calibrate "
                    f'with "version": {active_version} for each of its guard points'
                )
            if new_status.unscored or not new_status.pairs:
                missing.append(
                    f"{new_status.unscored or 'all'} golden examples have no stored score under "
                    "this draft's wording: POST /draft/calibrate for each of its guard points"
                )
            if missing:
                failures.append(
                    GateFailure(
                        rule.id,
                        "regression",
                        "recall can't be compared: " + "; ".join(missing) + REWORDED_HINT,
                    )
                )
                continue
            old_at, new_at = (
                _escalate_at(compiled_old, was, key),
                _escalate_at(compiled_new, rule, key),
            )
            if old_at is None or new_at is None:
                continue
            compared = compare_recall(old_status, new_status, old_at, new_at)
            if compared is None:
                continue  # no golden positives: nothing to measure
            fell = (compared.before - compared.after) * 100
            if fell > tolerance + 1e-9:
                failures.append(
                    GateFailure(
                        rule.id,
                        "regression",
                        f"recall fell {fell:.1f} points, over the tolerance of {tolerance:g}: "
                        f"{compared.before:.3f} on the active version v{active_version} "
                        f"(acting at p >= {old_at}) to {compared.after:.3f} on this one "
                        f"(p >= {new_at}), over {compared.positives} golden positives "
                        f"({compared.composition(new_status)})",
                    )
                )
            else:
                parts.append(
                    f"{rule.id} {compared.before:.2f}->{compared.after:.2f} "
                    f"{compared.composition(new_status)}"
                )
        record = f"regression gate: tolerance {tolerance:g} pt vs v{active_version}; " + (
            "; ".join(parts) if parts else "no rule compared"
        )
        return failures, record

    # ---------------------------------------------- the soak, replaced by the golden gates

    async def soak_replacement(
        self,
        scope: TenantScope,
        document: dict[str, Any],
        active_document: dict[str, Any] | None,
    ) -> dict[str, str]:
        """Which rules need no shadow soak, because the golden gates stand in for it (decided
        2026-11-18): a tenant rule that enforces in the active version, and whose **only**
        change in ``document`` is its thresholds (``block_at`` or ``escalate_at``), when all of
        these hold: the R1 precision gate passes for it; the regression gate passes for it; and
        its pool has **no unscored example** (under either version), at least
        :data:`SOAK_REPLACEMENT_MIN_EXAMPLES` scored examples and at least
        :data:`SOAK_REPLACEMENT_MIN_SIDE` positives and negatives. A smaller or lopsided pool
        keeps the soak. A floor-derived rule gets no exemption. Returns ``{rule id: the numbers}``
        for the record, e.g. ``refunds p=1.00@0.9 r=0.92->0.92 n=48 pos=24 neg=24``."""
        if active_document is None:
            return {}
        profile = await self._tenants.get(scope.tenant_id)
        if profile is None:
            raise TenantUnavailableError()
        new, shape = read_bundle(document)
        old, old_shape = read_bundle(active_document)
        if new is None or shape or old is None or old_shape:
            return {}
        try:
            compiled_old = self._compiled_for_measuring(old, profile)
        except PolicyInvalidError:
            return {}  # can't measure it: no exemption
        compiled_new = self._compiled(new, profile)
        targets = (await self.targets_for(scope)).targets
        derived_new = floor_derived_keys(self._catalog, new)
        derived_old = floor_derived_keys(self._catalog, old)
        floor_new, floor_old = floor_refs(new), floor_refs(old)
        old_rules = {r.id: r for r in old.bundle.rules}
        exempt: dict[str, str] = {}
        for rule in new.bundle.rules:
            key = f"t__{rule.id}"
            was = old_rules.get(rule.id)
            if (
                rule.mode != "enforce"
                or key in derived_new
                or was is None
                or was.mode != "enforce"
                or key in derived_old
                or _without_thresholds(rule) != _without_thresholds(was)
            ):
                continue
            new_status = await self._scores_for(scope, compiled_new, new, floor_new, rule, key)
            old_status = await self._scores_for(scope, compiled_old, old, floor_old, was, key)
            if (
                new_status.unscored
                or old_status.unscored
                or len(new_status.pairs) < SOAK_REPLACEMENT_MIN_EXAMPLES
                or new_status.positives < SOAK_REPLACEMENT_MIN_SIDE
                or new_status.negatives < SOAK_REPLACEMENT_MIN_SIDE
            ):
                continue
            block_at = _block_at(compiled_new, rule, key)
            old_at, new_at = (
                _escalate_at(compiled_old, was, key),
                _escalate_at(compiled_new, rule, key),
            )
            if block_at is None or old_at is None or new_at is None:
                continue
            point = precision_at(new_status.pairs, block_at)
            if point.precision is None or point.precision < targets.block_precision:
                continue
            compared = compare_recall(old_status, new_status, old_at, new_at)
            if compared is None:
                continue
            if (compared.before - compared.after) * 100 > targets.recall_tolerance + 1e-9:
                continue
            exempt[rule.id] = (
                f"{rule.id} p={point.precision:.2f}@{block_at} "
                f"r={compared.before:.2f}->{compared.after:.2f} {new_status.composition}"
            )
        return exempt


FLOOR_MOVED = frozenset({"floor.below_minimum", "floor.not_released"})
"""The compile errors that mean the platform moved the active version's floor: the one case in
which the active version isn't measured and the regression gate says so instead of failing."""
REWORDED_HINT = (
    " (a rule reworded at the same guard point changes the scoring identity of all of them: "
    "calibrate that guard point again, for the draft and for the active version)"
)
OTHER_TERMINAL = frozenset({"too_large", "refused", "held"})
"""Unscorable causes that leave an example out of both versions' recall (the intersection of
the two pools). ``deterministic`` is not among them: that content is blocked either way, so it
counts as acted on."""


@dataclass(frozen=True, slots=True)
class RecallComparison:
    before: float
    after: float
    positives: int
    left_out: dict[str, int]

    def composition(self, new_status: PoolStatus) -> str:
        """The draft's pool for a record, and, if any positives were left out of one version
        (an unscorable cause), how many by cause."""
        text = new_status.composition
        if self.left_out:
            text += " left_out=" + ",".join(f"{c}:{n}" for c, n in sorted(self.left_out.items()))
        return text


def compare_recall(
    old: PoolStatus, new: PoolStatus, old_at: float, new_at: float
) -> RecallComparison | None:
    """Recall of the active version against the draft over the **same** golden positives: the
    examples both versions' pools hold. A positive that a tenant deny pattern or PII block stops
    before the model (``deterministic``) counts as acted on in the version where it does: the
    content is blocked anyway. A positive one version can't score for another
    reason (too large, refused, held) is left out of both. ``None`` with no positives."""
    before = after = positives = 0
    left_out: dict[str, int] = {}
    for at in old.items.keys() & new.items.keys():
        o, n = old.items[at], new.items[at]
        if not o.positive:
            continue
        cause = next((c for c in (o.cause, n.cause) if c in OTHER_TERMINAL), None)
        if cause is not None:
            left_out[cause] = left_out.get(cause, 0) + 1
            continue
        positives += 1
        before += _acted(o, old_at)
        after += _acted(n, new_at)
    if positives == 0:
        return None
    return RecallComparison(before / positives, after / positives, positives, left_out)


def _acted(item: ItemState, threshold: float) -> bool:
    if item.cause == "deterministic":
        return True
    return item.p is not None and item.p >= threshold - 1e-9


def _cannot_measure(rules: Sequence[Any], version: int, why: str) -> tuple[list[GateFailure], str]:
    """The active version can't be measured and it isn't the floor case: refuse each rule that
    would have been compared."""
    failures = [
        GateFailure(
            rule.id,
            "regression",
            f"recall can't be compared: the active version v{version} can't be measured ({why})",
        )
        for rule in rules
    ]
    return failures, f"regression gate: v{version} can't be measured ({why})"


SOAK_REPLACEMENT_MIN_EXAMPLES = 20
"""A rule's scored pool must hold at least this many examples for the golden gates to stand in
for its shadow soak after a thresholds-only change."""
SOAK_REPLACEMENT_MIN_SIDE = 10
"""... and at least this many positives and this many negatives: a pool of 19 allows
and one block can't show either gate anything."""

THRESHOLD_FIELDS = ("block_at", "escalate_at")


def _without_thresholds(rule: Any) -> dict[str, Any]:
    """The rule as a dict without ``block_at`` and ``escalate_at``: what must be unchanged
    for a change to be a thresholds-only change."""
    return {k: v for k, v in rule.model_dump(mode="json").items() if k not in THRESHOLD_FIELDS}


def _block_at(compiled: Any, rule: Any, key: str) -> float | None:
    for gp in sorted(rule.guard_points):
        cgp = compiled.guard_points.get(gp)
        if cgp is not None and key in cgp.rules:
            return cgp.rules[key].block_at
    return None


def _escalate_at(compiled: Any, rule: Any, key: str) -> float | None:
    """The rule's effective ``escalate_at`` in a compiled version: where it starts to act."""
    for gp in sorted(rule.guard_points):
        cgp = compiled.guard_points.get(gp)
        if cgp is not None and key in cgp.rules:
            return cgp.rules[key].escalate_at
    return None


def _left_out(status: PoolStatus) -> str:
    """The examples that can't be scored and so are not in the pool, as counts by cause."""
    if not status.excluded:
        return ""
    return f" ({status.excluded_text} left out of the pool: they can't be scored)"


def _suggested(found: RuleSuggestion) -> dict[str, Any] | None:
    s = found.suggestion
    if not s.available:
        return {"available": False, "reason": s.reason}
    return {
        "available": True,
        "block_at": s.block_at,
        "escalate_at": s.escalate_at,
        "band_empty": s.band_empty,
        "precision": s.precision,
        "examples": s.examples,
        "scored": found.scored,
        "unscored": found.unscored,
        "excluded": dict(found.excluded),
    }


_CALIBRATE_FIELDS = {"guard_point", "version"}


def _parse_calibrate(body: bytes) -> tuple[str, int | None]:
    doc, problems = parse_json_text(body)
    if problems:
        raise DraftInvalidError(_convert(problems))
    if not isinstance(doc, dict) or set(doc) - _CALIBRATE_FIELDS:
        raise _fail("calibrate.request", "$", "an object with guard_point and optionally version")
    guard_point = doc.get("guard_point")
    if guard_point not in GUARD_POINTS:
        raise _fail("calibrate.guard_point", "$.guard_point", f"one of {', '.join(GUARD_POINTS)}")
    version = doc.get("version")
    if version is not None and (
        isinstance(version, bool) or not isinstance(version, int) or version < 1
    ):
        raise _fail("calibrate.version", "$.version", "a version number, 1 or more")
    return guard_point, version


def _parse_decisions(body: bytes) -> tuple[str | None, dict[str, dict[str, Any]]]:
    """``{"rules": {"<rule id>": {"action": "accept"} | {"action": "override", "block_at": x,
    "escalate_at": y, "reason"?: text}}}``, strictly."""
    doc, problems = parse_json_text(body)
    if problems:
        raise DraftInvalidError(_convert(problems))
    errors: list[DraftError] = []

    def bad(code: str, path: str, message: str) -> None:
        errors.append(DraftError(f"thresholds.{code}", path, message))

    if not isinstance(doc, dict) or set(doc) - {"rules", "digest"}:
        raise _fail("thresholds.request", "$", "an object with rules and, to accept, digest")
    digest = doc.get("digest")
    if digest is not None and (
        not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
    ):
        raise _fail("thresholds.digest", "$.digest", "the digest /validate returned")
    rules = doc.get("rules")
    out: dict[str, dict[str, Any]] = {}
    if not isinstance(rules, dict) or not rules:
        raise _fail("thresholds.rules", "$.rules", "an object keyed by rule id")
    for rule_id, want in rules.items():
        path = f"$.rules.{rule_id}"
        if not isinstance(rule_id, str) or not _RULE_ID.fullmatch(rule_id):
            bad("rule_id", path, "a rule id")
            continue
        if not isinstance(want, dict) or want.get("action") not in ("accept", "override"):
            bad("action", f"{path}.action", "accept or override")
            continue
        allowed = {"action", "reason"} | (
            {"block_at", "escalate_at"} if want["action"] == "override" else set()
        )
        for extra in sorted(set(want) - allowed):
            bad("unknown_field", f"{path}.{extra}", "not a field of this decision")
        reason = want.get("reason")
        if reason is not None and (
            not isinstance(reason, str) or not 1 <= len(reason) <= MAX_REASON_CHARS
        ):
            bad("reason", f"{path}.reason", f"text of 1 to {MAX_REASON_CHARS} characters")
        if want["action"] == "override":
            for name in ("block_at", "escalate_at"):
                value = want.get(name)
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    bad(name, f"{path}.{name}", "a number")
        out[rule_id] = want
    if errors:
        raise DraftInvalidError(errors)
    return digest, out
