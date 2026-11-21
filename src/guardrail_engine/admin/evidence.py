"""The R1 evidence gate (M2-07): a tenant rule may enforce only on evidence.

Applies to a publish or a promotion that would enforce, and to each tenant (``t__``) rule whose
own ``mode`` is ``enforce`` (the default). A rule in ``shadow`` is exempt, so is every floor and
pack rule (they carry platform calibration), and a fork of a pack rule is treated as free text.
A new tenant rule therefore starts with rule-level ``mode: shadow`` inside whatever version it
is published in.

* **Label counts.** For each guard point the rule runs on, at least 20 labelled examples with at
  least 5 ``block`` and 5 ``allow``; a ``severity: high`` rule needs at least 50 with 15 on each
  side. Counted over all of the tenant's golden sets, **de-duplicated by content within a guard
  point**, leaving out quarantined rows (they can never be run) and any content that carries
  both labels (it proves nothing). Golden examples are per guard point, not per rule, so every
  rule at a guard point shares the pool.
* **Shadow soak.** At least 72 hours of **continuous time the rule, as worded now, was live
  inside the active version**: in rule-mode ``shadow``, or enforcing with the same wording and
  thresholds (a rule that enforces already has its soak: an unrelated edit doesn't restart it;
  decided 2026-11-18), read from the class A events: each activation (first publish,
  promotion, rollback) sets what is live. A candidate does not
  count, whatever its mode or share, because it serves no traffic until M4-03; an abandoned
  candidate leaves no soak. An activation of a version that no longer carries the rule in
  shadow, or carries it reworded or thresholds changed (the fingerprint), restarts the clock.
  A rule with ``template_unedited: true`` is exempt from the soak, not from the counts.

* **Precision (M4-01).** The rule's ``block_at`` must meet the tenant's precision target
  (default 0.95) on the rule's golden pool, computed as in B2 from the stored probabilities
  of **every** example in it (:mod:`guardrail_engine.admin.calibration`). A rule with examples
  that haven't been scored, or with nothing predicted at its ``block_at``, fails. A floor-derived
  tenant rule is exempt (it is the floor's rule under another key). Every result records the
  targets, the bundle and the floor version it used.

* **Soak replaced by the golden gates (M4-02, decided 2026-11-18).** A tenant rule that enforces
  in the active version and whose **only** change is its thresholds is exempt from the soak when
  the precision gate and the regression gate pass for it and its golden pool holds at least 20
  scored examples with none unscored. A smaller pool keeps the soak; a floor-derived rule gets no
  exemption; the record says "soak replaced by golden gates" with the numbers.
* **Regression (M4-02, AC-A3).** An enforcing tenant rule that was also enforcing in the active
  version may not lose more than the tenant's tolerance (default 2 points) of golden-set recall
  against it, computed from stored scores at each version's thresholds
  (:mod:`guardrail_engine.admin.calibration`). Unscored examples fail closed. The first publish
  has nothing to compare and passes, and its record says so.

A failure names the rule, the gate and the guard point, with the numbers, and every failing rule
is listed together. The clock is injected.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Protocol

from guardrail_engine.admin.golden import ScopedGoldenStores
from guardrail_engine.admin.lifecycle import PublishEvent, RuleSnapshot, rule_snapshots
from guardrail_engine.tenant_scope import TenantScope

SOAK = timedelta(hours=72)
STANDARD = (20, 5)
"""(examples in all, examples on each side)."""
HIGH_SEVERITY = (50, 15)


@dataclass(frozen=True, slots=True)
class GateFailure:
    rule_id: str
    gate: str
    """``label_counts``, ``shadow_soak``, ``precision`` or ``regression``."""
    message: str
    guard_point: str | None = None

    @property
    def code(self) -> str:
        return f"evidence_gate.{self.gate}"


def _need(severity: object) -> tuple[int, int]:
    return HIGH_SEVERITY if severity == "high" else STANDARD


class PrecisionGate(Protocol):
    """The R1 precision gate (M4-01): ``CalibrationService`` implements it."""

    async def precision_gate(
        self, scope: TenantScope, document: dict[str, Any]
    ) -> tuple[list[GateFailure], str]:
        """The precision failures for the document's enforcing tenant rules, and a one-line
        record of the targets, bundle and floor version the result used."""
        ...


class _NoPrecisionGate:
    """The explicit opt-out of the precision check (a test of something else, or an embedder
    with no calibration). Passing nothing is not an opt-out: it fails closed."""

    async def precision_gate(
        self, scope: TenantScope, document: dict[str, Any]
    ) -> tuple[list[GateFailure], str]:
        return [], ""


NO_PRECISION_GATE: PrecisionGate = _NoPrecisionGate()


class RegressionGate(Protocol):
    """The AC-A3 regression gate (M4-02): ``CalibrationService`` implements it."""

    async def regression_gate(
        self,
        scope: TenantScope,
        document: dict[str, Any],
        active_version: int | None,
        active_document: dict[str, Any] | None,
    ) -> tuple[list[GateFailure], str]:
        """The failures for the document's rules that lose more recall than the tenant's
        tolerance against the active version's, and a one-line record of the comparison."""
        ...

    async def soak_replacement(
        self,
        scope: TenantScope,
        document: dict[str, Any],
        active_document: dict[str, Any] | None,
    ) -> dict[str, str]:
        """The rules whose shadow soak the golden gates replace (a thresholds-only change to a
        rule that enforces, with both gates passing and a pool of 20 or more with nothing
        unscored), each with the numbers for the record."""
        ...


class _NoRegressionGate:
    """The explicit opt-out of the regression check (a test of something else, or an embedder
    with no calibration). Passing nothing is not an opt-out: it fails closed once there is an
    active version to compare with."""

    async def regression_gate(
        self,
        scope: TenantScope,
        document: dict[str, Any],
        active_version: int | None,
        active_document: dict[str, Any] | None,
    ) -> tuple[list[GateFailure], str]:
        return [], ""

    async def soak_replacement(
        self,
        scope: TenantScope,
        document: dict[str, Any],
        active_document: dict[str, Any] | None,
    ) -> dict[str, str]:
        return {}


NO_REGRESSION_GATE: RegressionGate = _NoRegressionGate()

RECORD_CHARS = 240
"""Each gate's record is cut to this many characters before it joins the other in the event's
note (the note holds at most 500)."""


def _clip(text: str) -> str:
    return text if len(text) <= RECORD_CHARS else text[: RECORD_CHARS - 1] + "…"


class EvidenceGate:
    """``precision`` is the R1 precision source. **Leaving it out fails closed**: every
    enforcing tenant rule is refused with ``evidence_gate.precision``, because a gate that skips
    its precision check when nothing is wired would let an uncalibrated rule enforce. Pass
    :data:`NO_PRECISION_GATE` to opt out on purpose. ``regression`` is the AC-A3 source, and the
    same holds once there is an active version to compare with: leaving it out refuses
    each enforcing rule with ``evidence_gate.regression``, and :data:`NO_REGRESSION_GATE` is the
    explicit opt-out."""

    def __init__(
        self,
        golden: ScopedGoldenStores | None,
        precision: PrecisionGate | None = None,
        regression: RegressionGate | None = None,
    ) -> None:
        self._golden = golden
        self._precision = precision
        self._regression = regression

    async def check(
        self,
        scope: TenantScope,
        document: dict[str, Any],
        history: Sequence[PublishEvent],
        now: datetime,
        *,
        active_version: int | None = None,
        active_document: dict[str, Any] | None = None,
    ) -> list[GateFailure]:
        """Every failure for the document's enforcing tenant rules. Empty means it may enforce."""
        return (
            await self.evaluate(
                scope, document, history, now,
                active_version=active_version, active_document=active_document,
            )
        )[0]  # fmt: skip

    async def evaluate(
        self,
        scope: TenantScope,
        document: dict[str, Any],
        history: Sequence[PublishEvent],
        now: datetime,
        *,
        active_version: int | None = None,
        active_document: dict[str, Any] | None = None,
    ) -> tuple[list[GateFailure], str]:
        """The failures, and (when the precision gate ran) the record of what it used, which
        the publish event carries so a past decision can be explained from its own record."""
        rules = [
            r
            for r in document.get("rules", [])
            if isinstance(r, dict)
            and isinstance(r.get("id"), str)
            and r.get("mode", "enforce") == "enforce"
        ]
        if not rules:
            return [], ""
        counts: dict[str, dict[str, int]] = {}
        from_escalations: dict[str, dict[str, int]] = {}
        if self._golden is not None:
            golden = self._golden.scoped(scope)
            counts = await golden.label_counts(scope.tenant_id)
            from_escalations = await golden.escalation_label_counts(scope.tenant_id)
        fingerprints = {s.id: s.fingerprint for s in rule_snapshots(document)}
        live_since = _live_shadow_since(history)
        failures: list[GateFailure] = []
        for rule in rules:
            rule_id = rule["id"]
            total_needed, side_needed = _need(rule.get("severity"))
            for gp in sorted(rule.get("guard_points", [])):
                by_label = counts.get(gp, {})
                allow, block = by_label.get("allow", 0), by_label.get("block", 0)
                if allow + block < total_needed or allow < side_needed or block < side_needed:
                    esc = from_escalations.get(gp, {})
                    esc_n = esc.get("allow", 0) + esc.get("block", 0)
                    # Escalation labels are counted, and shown apart (they are not in
                    # the default golden-set list; ?include=escalation lists them).
                    esc_note = (
                        f", of which {esc_n} from escalation labels ({esc.get('block', 0)} "
                        f"block, {esc.get('allow', 0)} allow)"
                        if esc_n
                        else ""
                    )
                    failures.append(
                        GateFailure(
                            rule_id,
                            "label_counts",
                            f"{gp}: {allow + block} labelled examples ({block} block, {allow} "
                            f"allow{esc_note}); an enforcing rule needs {total_needed} with at "
                            f"least {side_needed} of each",
                            gp,
                        )
                    )
            if rule.get("template_unedited") is True:
                continue  # exempt from the soak, not from the counts
            since = live_since.get((rule_id, fingerprints[rule_id]))
            if since is None:
                failures.append(
                    GateFailure(
                        rule_id,
                        "shadow_soak",
                        "this rule, as worded now, is not live in the active version (in rule-mode "
                        "shadow, or enforcing with these same thresholds); publish it with rule "
                        "mode shadow, promote that version and let "
                        "it soak for 72 hours",
                    )
                )
            elif now - since < SOAK:
                hours = (SOAK - (now - since)).total_seconds() / 3600
                failures.append(
                    GateFailure(
                        rule_id,
                        "shadow_soak",
                        f"live in shadow in the active version since {since.isoformat()}; "
                        f"{hours:.1f} more hours of the 72 are needed",
                    )
                )
        records: list[str] = []
        if self._precision is None:
            failures.extend(
                GateFailure(
                    r["id"],
                    "precision",
                    "no precision source is configured for the evidence gate, so the rule "
                    "can't be shown to meet its precision target",
                )
                for r in rules
            )
        else:
            precision_failures, precision_record = await self._precision.precision_gate(
                scope, document
            )
            failures.extend(precision_failures)
            records.append(precision_record)
        if self._regression is None:
            if active_version is not None:  # the first publish has nothing to compare with
                failures.extend(
                    GateFailure(
                        r["id"],
                        "regression",
                        "no regression source is configured for the evidence gate, so the "
                        "rule's recall can't be compared with the active version's",
                    )
                    for r in rules
                )
        else:
            regression_failures, regression_record = await self._regression.regression_gate(
                scope, document, active_version, active_document
            )
            failures.extend(regression_failures)
            records.append(regression_record)
        soaks = {f.rule_id for f in failures if f.gate == "shadow_soak"}
        if soaks and self._regression is not None:
            exempt = await self._regression.soak_replacement(scope, document, active_document)
            exempt = {rule_id: text for rule_id, text in exempt.items() if rule_id in soaks}
            if exempt:
                failures = [
                    f for f in failures if not (f.gate == "shadow_soak" and f.rule_id in exempt)
                ]
                records.append("soak replaced by golden gates: " + "; ".join(exempt.values()))
        return failures, "\n".join(_clip(r) for r in records if r)


def _live_shadow_since(history: Sequence[PublishEvent]) -> dict[tuple[str, str], datetime]:
    """For each (rule id, fingerprint) that is **live in the active version**, in rule-mode
    shadow **or enforcing**, since when it has been, continuously (and the carry-over
    decided 2026-11-18).

    Read from the ordered events: each activation (the first publish, a promotion or a
    rollback, ``becomes_active``) replaces the set of live rules with those of the version that
    became active. A rule that stays, with the same fingerprint, keeps its start, whether it
    moved from shadow to enforce or has been enforcing all along; one that is new to the active
    version starts at its activation; one the new active version doesn't carry, or carries
    reworded or with other thresholds (another fingerprint), loses it, so it restarts if it
    comes back. A rule that enforces in the active version therefore **has its soak** for the
    next enforce publish that keeps it as it is: an unrelated edit to the bundle doesn't ask for
    72 hours in shadow again. A candidate (shadow or not) does not count: it serves no traffic
    until M4-03, so an abandoned candidate leaves no soak behind."""
    rules_of: dict[int, tuple[RuleSnapshot, ...]] = {}
    version_mode: dict[int, str | None] = {}
    live: dict[tuple[str, str], datetime] = {}
    for event in history:
        if event.action == "publish":
            rules_of[event.version] = event.rules
            version_mode[event.version] = event.mode
        elif event.action == "promote":
            version_mode[event.version] = "enforce"  # a promotion makes it decide all traffic
        if not event.becomes_active:
            continue
        # A rule is live if it is in rule-mode shadow, or it enforces in a version that enforces
        # (a version published in shadow acts on nothing, whatever its rules' own mode says).
        carried = {
            (s.id, s.fingerprint)
            for s in rules_of.get(event.version, ())
            if s.mode == "shadow" or version_mode.get(event.version) != "shadow"
        }
        live = {key: live.get(key, event.at) for key in carried}
    return live
