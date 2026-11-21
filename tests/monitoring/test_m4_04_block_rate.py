"""M4-04: the bad-publish block-rate alert and the provider-health alert. Time is injected."""

import logging
from datetime import UTC, datetime

import pytest

from guardrail_engine.gateway.sinks import (
    ALERT_BAD_PUBLISH,
    ALERT_PROVIDER_HEALTH,
    AlertSeverity,
    RecordingAlertSink,
)
from guardrail_engine.guard.audit import InMemoryAuditSink
from guardrail_engine.guard.verdict import Decision, Reason, Verdict
from guardrail_engine.monitoring import BadPublishDetector, BlockRateConfig, Outcome

HOUR = 3600.0
MINUTE = 60.0
# A whole hour, so minute and hour buckets line up: 2026-11-10 00:00:00 UTC.
T0 = 1_794_268_800.0 - (1_794_268_800.0 % HOUR)
PUBLISH = T0 + 3 * 24 * HOUR  # baseline history sits before this


class Clock:
    def __init__(self, now: float = T0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


class Rig:
    def __init__(self, **config) -> None:
        self.clock = Clock()
        self.alerts = RecordingAlertSink()
        self.det = BadPublishDetector(
            self.alerts, config=BlockRateConfig(**config), clock=self.clock
        )

    def traffic(
        self,
        at: float,
        checks: int,
        blocks: int,
        tenant: str = "t_a",
        *,
        spread: float = 0.0,
    ) -> None:
        """``checks`` policy-decided checks, ``blocks`` of them policy blocks, spread over
        ``spread`` seconds from ``at``."""
        for i in range(checks):
            self.clock.now = at + (spread * i / checks if checks else 0)
            block = i < blocks
            self.det.observe(
                tenant,
                Decision.BLOCK if block else Decision.ALLOW,
                Reason.POLICY,
            )

    def baseline(self, checks: int = 1000, blocks: int = 50, tenant: str = "t_a") -> None:
        """Three days of history before the publish, at ``blocks``/``checks``."""
        self.traffic(PUBLISH - 2 * 24 * HOUR, checks, blocks, tenant, spread=24 * HOUR)

    def publish(self, version: int = 2, action: str = "publish", tenant: str = "t_a") -> None:
        self.clock.now = PUBLISH
        self.det.note_publish(tenant, version, action)

    def window(self, checks: int, blocks: int, tenant: str = "t_a") -> None:
        """Traffic in the 15 minutes after the publish."""
        self.traffic(PUBLISH + 1 * MINUTE, checks, blocks, tenant, spread=13 * MINUTE)

    def tick_at(self, seconds_after_publish: float):
        self.clock.now = PUBLISH + seconds_after_publish
        return self.det.tick()


class TestThresholdEdges:
    def test_a_rate_above_twice_the_baseline_alerts_with_the_rollback(self):
        rig = Rig()
        rig.det.note_publish("t_a", 1, "publish")  # the version being replaced
        rig.baseline(1000, 50)  # 5%
        rig.publish(version=2)
        rig.window(200, 21)  # 10.5% > 10%
        [result] = rig.tick_at(15 * MINUTE)
        assert result.outcome is Outcome.ALERTED
        [alert] = rig.alerts.alerts
        assert alert.kind == ALERT_BAD_PUBLISH
        assert alert.severity is AlertSeverity.PAGE
        assert alert.tenant_id == "t_a"
        assert alert.reason == "policy"
        assert alert.rollback == "/v1/tenants/t_a/guardrails/versions/1/rollback"
        assert "version 2" in alert.message

    def test_exactly_twice_the_baseline_does_not_alert(self):
        rig = Rig()
        rig.baseline(1000, 50)  # 5%
        rig.publish()
        rig.window(200, 20)  # exactly 10%
        [result] = rig.tick_at(15 * MINUTE)
        assert result.outcome is Outcome.NORMAL
        assert rig.alerts.alerts == []

    def test_one_block_over_the_edge_alerts(self):
        rig = Rig()
        rig.baseline(1000, 50)
        rig.publish()
        rig.window(200, 21)
        assert rig.tick_at(15 * MINUTE)[0].outcome is Outcome.ALERTED

    def test_the_multiplier_is_configurable(self):
        rig = Rig(multiplier=3.0)
        rig.baseline(1000, 50)
        rig.publish()
        rig.window(200, 25)  # 12.5%: above 2x, below 3x
        assert rig.tick_at(15 * MINUTE)[0].outcome is Outcome.NORMAL

    def test_fourteen_minutes_fifty_nine_seconds_is_too_early_and_fifteen_evaluates(self):
        rig = Rig()
        rig.baseline()
        rig.publish()
        rig.window(200, 100)
        assert rig.tick_at(15 * MINUTE - 1) == []
        assert rig.alerts.alerts == []
        assert rig.det.watching == ["t_a"]
        assert len(rig.tick_at(15 * MINUTE)) == 1
        assert len(rig.alerts.alerts) == 1
        assert rig.det.watching == []

    def test_traffic_after_the_window_does_not_count(self):
        rig = Rig()
        rig.baseline()
        rig.publish()
        rig.window(200, 5)  # 2.5%: fine
        rig.traffic(PUBLISH + 15 * MINUTE, 500, 500)  # a block storm in the 16th minute
        [result] = rig.tick_at(17 * MINUTE)
        assert (result.window_checks, result.window_blocks) == (200, 5)
        assert result.outcome is Outcome.NORMAL

    def test_a_mid_minute_publish_counts_whole_minutes_after_it(self):
        rig = Rig()
        rig.baseline()
        rig.clock.now = PUBLISH + 30
        rig.det.note_publish("t_a", 2, "publish")
        rig.traffic(PUBLISH + 10, 50, 50)  # same minute as the publish, before it: left out
        rig.traffic(PUBLISH + 61, 200, 100)
        assert rig.tick_at(15 * MINUTE + 30) == []  # the 15th minute has not ended
        [result] = rig.tick_at(16 * MINUTE)
        assert (result.window_checks, result.window_blocks) == (200, 100)

    def test_a_zero_baseline_alerts_on_enough_blocks_and_not_on_noise(self):
        rig = Rig()
        rig.baseline(1000, 0)
        rig.publish()
        rig.window(100, 2)  # under min_window_blocks
        assert rig.tick_at(15 * MINUTE)[0].outcome is Outcome.TOO_FEW_CHECKS
        rig = Rig()
        rig.baseline(1000, 0)
        rig.publish()
        rig.window(100, 3)
        assert rig.tick_at(15 * MINUTE)[0].outcome is Outcome.ALERTED

    def test_a_thin_window_is_too_few_checks_not_an_alert(self):
        rig = Rig()
        rig.baseline(1000, 50)
        rig.publish()
        rig.window(19, 19)  # all blocked, but under min_window_checks
        assert rig.tick_at(15 * MINUTE)[0].outcome is Outcome.TOO_FEW_CHECKS
        assert rig.alerts.alerts == []

    def test_one_alert_per_publish(self):
        rig = Rig()
        rig.baseline()
        rig.publish()
        rig.window(200, 100)
        rig.tick_at(15 * MINUTE)
        assert rig.tick_at(20 * MINUTE) == []
        assert len(rig.alerts.alerts) == 1

    def test_the_baseline_stops_at_the_hour_of_the_publish(self):
        rig = Rig()
        rig.baseline(1000, 50)
        # Bad traffic in the publish hour but before the publish: not part of the baseline.
        rig.traffic(PUBLISH + 5 * MINUTE, 1000, 1000)
        rig.clock.now = PUBLISH + 30 * MINUTE
        rig.det.note_publish("t_a", 2, "publish")
        rig.traffic(PUBLISH + 31 * MINUTE, 200, 21, spread=13 * MINUTE)
        rig.clock.now = PUBLISH + 46 * MINUTE
        [result] = rig.det.tick()
        assert (result.baseline_checks, result.baseline_blocks) == (1000, 50)
        assert result.outcome is Outcome.ALERTED

    def test_the_baseline_reaches_back_seven_days_and_no_further(self):
        rig = Rig()
        rig.traffic(PUBLISH - 8 * 24 * HOUR, 5000, 5000)  # too old
        rig.traffic(PUBLISH - 6 * 24 * HOUR, 1000, 50)
        rig.publish()
        rig.window(200, 21)
        [result] = rig.tick_at(15 * MINUTE)
        assert (result.baseline_checks, result.baseline_blocks) == (1000, 50)


class TestNoBaseline:
    """With no baseline there is no alert (documented in docs/m4-04-bad-publish-detection.md)."""

    def test_a_tenant_with_no_history_never_alerts_however_high_the_rate(self, caplog):
        rig = Rig()
        rig.publish()
        rig.window(500, 500)
        with caplog.at_level(logging.INFO):
            [result] = rig.tick_at(15 * MINUTE)
        assert result.outcome is Outcome.NO_BASELINE
        assert rig.alerts.alerts == []
        assert any("no bad-publish check" in r.getMessage() for r in caplog.records)

    def test_a_baseline_under_the_minimum_is_no_baseline(self):
        rig = Rig()
        rig.baseline(99, 0)
        rig.publish()
        rig.window(500, 500)
        assert rig.tick_at(15 * MINUTE)[0].outcome is Outcome.NO_BASELINE

    def test_a_baseline_at_the_minimum_counts(self):
        rig = Rig()
        rig.baseline(100, 0)
        rig.publish()
        rig.window(500, 500)
        assert rig.tick_at(15 * MINUTE)[0].outcome is Outcome.ALERTED

    def test_another_tenants_history_is_not_this_tenants_baseline(self):
        rig = Rig()
        rig.baseline(1000, 50, tenant="t_other")
        rig.publish()
        rig.window(500, 500)
        assert rig.tick_at(15 * MINUTE)[0].outcome is Outcome.NO_BASELINE

    def test_a_restart_forgets_the_baseline(self):
        rig = Rig()
        rig.baseline(1000, 50)
        rig.publish()
        rig.window(200, 100)
        fresh = Rig()  # a new process: counters are in memory
        fresh.publish()
        fresh.window(200, 100)
        assert fresh.tick_at(15 * MINUTE)[0].outcome is Outcome.NO_BASELINE


class TestModelFailureIsExcluded:
    def test_model_failures_neither_raise_nor_dilute_the_policy_rate(self):
        rig = Rig()
        rig.baseline(1000, 50)
        rig.publish()
        rig.window(200, 20)  # exactly 2x
        for _ in range(500):  # a provider outage in the same window
            rig.det.observe("t_a", Decision.BLOCK, Reason.MODEL_FAILURE)
        [result] = rig.tick_at(15 * MINUTE)
        assert (result.window_checks, result.window_blocks) == (200, 20)
        assert result.outcome is Outcome.NORMAL

    def test_model_failures_in_the_baseline_are_not_baseline_traffic(self):
        rig = Rig()
        rig.baseline(1000, 50)
        rig.clock.now = PUBLISH - 5 * HOUR
        for _ in range(5000):
            rig.det.observe("t_a", Decision.BLOCK, Reason.MODEL_FAILURE)
        rig.publish()
        rig.window(200, 21)
        [result] = rig.tick_at(15 * MINUTE)
        assert (result.baseline_checks, result.baseline_blocks) == (1000, 50)
        assert result.outcome is Outcome.ALERTED

    def test_an_all_model_failure_window_is_no_bad_publish_but_is_provider_health(self):
        rig = Rig()
        rig.baseline(1000, 50)
        rig.publish()
        rig.clock.now = PUBLISH + 12 * MINUTE
        for _ in range(100):
            rig.det.observe("t_a", Decision.BLOCK, Reason.MODEL_FAILURE)
        [result] = rig.tick_at(15 * MINUTE)
        assert result.outcome is Outcome.TOO_FEW_CHECKS
        assert [a.kind for a in rig.alerts.alerts] == [ALERT_PROVIDER_HEALTH]

    @pytest.mark.parametrize(
        "decision, reason",
        [
            (Decision.BLOCK, Reason.POLICY_UNAVAILABLE),
            (Decision.BLOCK, Reason.INTERNAL_ERROR),
            (Decision.BLOCK, Reason.ENGINE_CLOSED),
            (Decision.BLOCK, Reason.INVALID_REQUEST),
            (Decision.BLOCK, Reason.PROVIDER_SAFETY),
            (Decision.BLOCK, Reason.CONTRACT_VIOLATION),
            (Decision.FORBIDDEN, Reason.TENANT_MISMATCH),
        ],
    )
    def test_reasons_that_say_nothing_about_the_rules_are_ignored(self, decision, reason):
        rig = Rig()
        rig.baseline(1000, 50)
        rig.publish()
        rig.window(200, 20)
        for _ in range(300):
            rig.det.observe("t_a", decision, reason)
        [result] = rig.tick_at(15 * MINUTE)
        assert (result.window_checks, result.window_blocks) == (200, 20)

    @pytest.mark.parametrize("reason", [Reason.DETERMINISTIC, Reason.CONTENT_TOO_LARGE])
    def test_a_tenant_caused_block_counts_in_the_numerator(self, reason):
        """A publish that adds a broad deny pattern or lowers max_input_tokens blocks
        traffic through the tenant's own configuration: that is a bad publish."""
        rig = Rig()
        rig.baseline(1000, 50)  # 5%
        rig.publish()
        rig.window(200, 20)  # 10%: exactly 2x, no alert yet
        for _ in range(100):
            rig.det.observe("t_a", Decision.BLOCK, reason)
        [result] = rig.tick_at(15 * MINUTE)
        assert (result.window_checks, result.window_blocks) == (300, 120)
        assert result.outcome is Outcome.ALERTED

    def test_a_deterministic_deny_pattern_publish_alerts_on_its_own(self):
        rig = Rig()
        rig.baseline(1000, 50)
        rig.publish()
        rig.traffic(PUBLISH + MINUTE, 200, 5, spread=13 * MINUTE)  # model-decided: 2.5%
        for _ in range(60):  # a new deny pattern blocks traffic before the model
            rig.det.observe("t_a", Decision.BLOCK, Reason.DETERMINISTIC)
        assert rig.tick_at(15 * MINUTE)[0].outcome is Outcome.ALERTED

    def test_an_allowed_no_questions_check_is_only_a_denominator(self):
        rig = Rig()
        rig.baseline(1000, 50)
        rig.publish()
        rig.window(200, 20)
        for _ in range(100):
            rig.det.observe("t_a", Decision.ALLOW, Reason.NO_QUESTIONS)
        [result] = rig.tick_at(15 * MINUTE)
        assert (result.window_checks, result.window_blocks) == (300, 20)

    def test_model_failure_is_excluded_from_the_rate_but_feeds_provider_health(self):
        rig = Rig()
        rig.baseline(1000, 50)
        rig.publish()
        rig.window(200, 20)
        for _ in range(100):
            rig.det.observe("t_a", Decision.BLOCK, Reason.MODEL_FAILURE)
        results = rig.tick_at(15 * MINUTE)
        assert (results[0].window_checks, results[0].window_blocks) == (200, 20)
        assert [a.kind for a in rig.alerts.alerts] == [ALERT_PROVIDER_HEALTH]


class TestWatches:
    def test_a_rollback_ends_the_watch(self):
        rig = Rig()
        rig.baseline()
        rig.publish()
        rig.window(200, 100)
        rig.clock.now = PUBLISH + 5 * MINUTE
        rig.det.note_publish("t_a", 1, "rollback")
        assert rig.tick_at(15 * MINUTE) == []
        assert rig.alerts.alerts == []

    def test_a_promote_starts_a_watch_and_set_percent_does_not(self):
        rig = Rig()
        rig.det.note_publish("t_a", 3, "set_percent")
        rig.det.note_publish("t_a", 3, "abandon")
        assert rig.det.watching == []
        rig.det.note_publish("t_a", 3, "promote")
        assert rig.det.watching == ["t_a"]

    def test_a_second_publish_restarts_the_window(self):
        rig = Rig()
        rig.baseline()
        rig.det.note_publish("t_a", 1, "publish")
        rig.publish(version=2)
        rig.clock.now = PUBLISH + 10 * MINUTE
        rig.det.note_publish("t_a", 3, "publish")
        rig.traffic(PUBLISH + 11 * MINUTE, 200, 100, spread=3 * MINUTE)
        assert rig.tick_at(15 * MINUTE) == []  # v2's window ended, but v3 replaced it
        [result] = rig.tick_at(25 * MINUTE)
        assert result.version == 3 and result.outcome is Outcome.ALERTED
        [alert] = rig.alerts.alerts
        assert alert.rollback.endswith("/versions/2/rollback")

    def test_without_a_known_previous_version_the_alert_points_at_the_versions_list(self):
        rig = Rig(rollback_prefix="https://admin.example")
        rig.baseline()
        rig.publish()
        rig.window(200, 100)
        rig.tick_at(15 * MINUTE)
        [alert] = rig.alerts.alerts
        assert alert.rollback == "https://admin.example/v1/tenants/t_a/guardrails/versions"

    def test_tenants_are_watched_separately(self):
        rig = Rig()
        for tenant in ("t_a", "t_b"):
            rig.baseline(1000, 50, tenant=tenant)
        rig.publish(tenant="t_a")
        rig.det.note_publish("t_b", 9, "publish")
        rig.window(200, 100, tenant="t_a")
        rig.window(200, 10, tenant="t_b")
        results = {r.tenant_id: r.outcome for r in rig.tick_at(15 * MINUTE)}
        assert results == {"t_a": Outcome.ALERTED, "t_b": Outcome.NORMAL}

    def test_on_published_takes_the_bus_event(self):
        from guardrail_engine.admin.lifecycle import GuardrailPublished

        rig = Rig()
        rig.det.on_published(GuardrailPublished("t_a", 4, "publish"))
        assert rig.det.watching == ["t_a"]

    def test_a_failing_alert_sink_does_not_break_the_tick(self, caplog):
        class Broken:
            def emit(self, alert):
                raise RuntimeError("down")

        rig = Rig()
        rig.det = BadPublishDetector(Broken(), clock=rig.clock)
        rig.baseline()
        rig.publish()
        rig.window(200, 100)
        assert rig.tick_at(15 * MINUTE)[0].outcome is Outcome.ALERTED
        assert any("could not hand" in r.getMessage() for r in caplog.records)

    def test_old_counters_are_dropped(self):
        rig = Rig()
        rig.baseline()
        rig.clock.now = PUBLISH + 30 * 24 * HOUR
        rig.det.tick()
        assert not rig.det._hours and not rig.det._minutes


class TestProviderHealth:
    def fail(self, rig, failures, ok, at):
        rig.clock.now = at
        for _ in range(failures):
            rig.det.observe("t_a", Decision.BLOCK, Reason.MODEL_FAILURE)
        for _ in range(ok):
            rig.det.observe("t_b", Decision.ALLOW, Reason.POLICY)

    def test_alerts_above_five_percent_across_tenants(self):
        rig = Rig()
        self.fail(rig, 6, 94, T0)
        rig.clock.now = T0 + 60
        rig.det.tick()
        [alert] = rig.alerts.alerts
        assert alert.kind == ALERT_PROVIDER_HEALTH and alert.tenant_id == ""
        assert alert.severity is AlertSeverity.PAGE
        assert alert.rollback is None
        assert "not a bad publish" in alert.message

    def test_exactly_five_percent_does_not_alert(self):
        rig = Rig()
        self.fail(rig, 5, 95, T0)
        rig.det.tick()
        assert rig.alerts.alerts == []

    def test_a_thin_sample_does_not_alert(self):
        rig = Rig()
        self.fail(rig, 10, 0, T0)  # all failed, but only 10 checks
        rig.det.tick()
        assert rig.alerts.alerts == []

    def test_one_page_while_it_lasts_and_no_repeat_by_default(self):
        rig = Rig()
        self.fail(rig, 50, 50, T0)
        rig.det.tick()
        rig.clock.now = T0 + 120
        rig.det.tick()
        self.fail(rig, 50, 50, T0 + 3600)  # still failing an hour later
        rig.det.tick()
        assert len(rig.alerts.alerts) == 1

    def test_a_reminder_can_be_switched_on(self):
        rig = Rig(provider_repeat_s=3600)
        self.fail(rig, 50, 50, T0)
        rig.det.tick()
        self.fail(rig, 50, 50, T0 + 3600)
        rig.det.tick()
        assert len(rig.alerts.alerts) == 2

    def test_a_rate_hovering_around_the_threshold_is_one_page(self):
        """A burst every six minutes keeps the trailing 5-minute rate crossing 5% and
        dropping below it for a minute: it is one incident, so one page."""
        rig = Rig()
        for minute in range(20):
            rig.clock.now = T0 + minute * 60
            for _ in range(100):
                rig.det.observe("t_b", Decision.ALLOW, Reason.POLICY)
            if minute % 6 == 0:
                for _ in range(30):
                    rig.det.observe("t_a", Decision.BLOCK, Reason.MODEL_FAILURE)
            rig.det.tick()
            rig.clock.now += 30
            rig.det.tick()
        assert len(rig.alerts.alerts) == 1
        # The same traffic without the hysteresis would have crossed three times.
        crossings = Rig(provider_clear_s=0)
        for minute in range(20):
            crossings.clock.now = T0 + minute * 60
            for _ in range(100):
                crossings.det.observe("t_b", Decision.ALLOW, Reason.POLICY)
            if minute % 6 == 0:
                for _ in range(30):
                    crossings.det.observe("t_a", Decision.BLOCK, Reason.MODEL_FAILURE)
            crossings.det.tick()
        assert len(crossings.alerts.alerts) >= 3

    def test_it_pages_again_only_after_five_healthy_minutes(self):
        rig = Rig()
        self.fail(rig, 50, 50, T0)
        rig.det.tick()
        assert len(rig.alerts.alerts) == 1
        # Healthy from the moment the failures leave the 5-minute window (T0 + 5 min).
        for seconds in range(6 * 60, 6 * 60 + 5 * 60, 30):  # 4 minutes 30 s of healthy ticks
            rig.clock.now = T0 + seconds
            rig.det.tick()
        self.fail(rig, 50, 50, T0 + 11 * 60)  # fails again before it has cleared
        rig.det.tick()
        assert len(rig.alerts.alerts) == 1
        # Now a full, unbroken healthy stretch of five minutes, then a new episode.
        for seconds in range(17 * 60, 23 * 60 + 1, 30):
            rig.clock.now = T0 + seconds
            rig.det.tick()
        self.fail(rig, 50, 50, T0 + 24 * 60)
        rig.det.tick()
        assert len(rig.alerts.alerts) == 2

    def test_the_page_has_a_deterministic_key_per_window(self):
        a, b = Rig(), Rig()
        for rig in (a, b):  # two replicas, ticking a few seconds apart
            self.fail(rig, 50, 50, T0)
        a.clock.now, b.clock.now = T0 + 61, T0 + 83
        a.det.tick()
        b.det.tick()
        [x], [y] = a.alerts.alerts, b.alerts.alerts
        assert x.dedupe_key and x.dedupe_key == y.dedupe_key
        assert x.dedupe_key.startswith("provider_health:")

    def test_failures_outside_the_trailing_window_do_not_count(self):
        rig = Rig()
        self.fail(rig, 50, 50, T0)
        rig.clock.now = T0 + 10 * MINUTE
        rig.det.tick()
        assert rig.alerts.alerts == []


class TestAuditTap:
    def verdict(self, decision, reason, tenant="t_a") -> Verdict:
        return Verdict(
            request_id="r",
            tenant_id=tenant,
            guard_point="output",
            decision=decision,
            reason=reason,
            checked_at=datetime.now(UTC),
            latency_ms=1.0,
        )

    def test_it_records_to_the_inner_sink_and_counts_the_verdict(self):
        rig = Rig()
        inner = InMemoryAuditSink()
        tapped = rig.det.audit_sink(inner)
        rig.det.note_publish("t_a", 2, "publish")
        tapped.record(self.verdict(Decision.BLOCK, Reason.POLICY))
        tapped.record(self.verdict(Decision.ALLOW, Reason.POLICY))
        rig.clock.now += 15 * MINUTE
        [result] = rig.det.tick()
        assert (result.window_checks, result.window_blocks) == (2, 1)
        assert len(inner.verdicts) == 2

    def test_a_verdict_with_no_tenant_is_ignored(self):
        rig = Rig()
        rig.det.observe_verdict(self.verdict(Decision.FORBIDDEN, Reason.CONTEXT_INVALID, None))
        assert not rig.det._minutes

    def test_the_inner_sink_failing_still_counts_and_raises(self):
        class Broken:
            def record(self, verdict):
                raise RuntimeError("full")

        rig = Rig()
        tapped = rig.det.audit_sink(Broken())
        with pytest.raises(RuntimeError):
            tapped.record(self.verdict(Decision.BLOCK, Reason.POLICY))
        assert rig.det._minutes["t_a"].total(0, 10**9) == (1, 1)


def test_config_rejects_nonsense():
    for bad in (
        {"window_s": 30},
        {"multiplier": 0},
        {"provider_threshold": 1.0},
        {"min_window_checks": -1},
    ):
        with pytest.raises(ValueError):
            BlockRateConfig(**bad)


class TestTwentyFourHourBaseline:
    """The in-memory baseline needs 24 hours of observations before it can fire."""

    def history(self, rig, hours_before_publish: float, checks=1000, blocks=50):
        span = hours_before_publish * HOUR - HOUR  # the baseline stops at the publish hour
        rig.traffic(PUBLISH - hours_before_publish * HOUR, checks, blocks, spread=span)

    def test_twenty_three_hours_of_history_is_no_baseline_and_logs_without_alerting(self, caplog):
        rig = Rig()
        self.history(rig, 23)
        rig.publish()
        rig.window(200, 100)
        with caplog.at_level(logging.INFO):
            [result] = rig.tick_at(15 * MINUTE)
        assert result.outcome is Outcome.NO_BASELINE
        assert result.baseline_checks == 1000  # enough checks, not enough time
        assert rig.alerts.alerts == []
        assert any("no bad-publish check" in r.getMessage() for r in caplog.records)

    def test_twenty_four_hours_of_history_is_a_baseline(self):
        rig = Rig()
        self.history(rig, 25)
        rig.publish()
        rig.window(200, 100)
        [result] = rig.tick_at(15 * MINUTE)
        assert result.outcome is Outcome.ALERTED
        assert result.baseline_observed_s >= 24 * HOUR

    def test_the_age_is_the_tenants_own_first_observation(self):
        rig = Rig()
        self.history(rig, 48)
        rig.traffic(PUBLISH - 2 * HOUR, 1000, 50, "t_new", spread=HOUR)  # a new tenant
        rig.publish()
        rig.det.note_publish("t_new", 5, "publish")
        rig.window(200, 100)
        rig.window(200, 100, tenant="t_new")
        results = {r.tenant_id: r.outcome for r in rig.tick_at(15 * MINUTE)}
        assert results == {"t_a": Outcome.ALERTED, "t_new": Outcome.NO_BASELINE}

    def test_a_restart_means_a_day_without_alerts_even_with_plenty_of_traffic(self):
        rig = Rig()
        rig.traffic(PUBLISH - 6 * HOUR, 5000, 250, spread=5 * HOUR)  # six hours since start
        rig.publish()
        rig.window(200, 100)
        assert rig.tick_at(15 * MINUTE)[0].outcome is Outcome.NO_BASELINE

    def test_the_age_is_configurable(self):
        rig = Rig(min_baseline_age_s=3 * HOUR)
        self.history(rig, 5)
        rig.publish()
        rig.window(200, 100)
        assert rig.tick_at(15 * MINUTE)[0].outcome is Outcome.ALERTED


class TestShadowPublishes:
    def test_a_shadow_publish_does_not_replace_the_enforce_watch(self):
        rig = Rig()
        rig.baseline()
        rig.det.note_publish("t_a", 1, "publish")
        rig.publish(version=2)  # an enforce publish
        rig.clock.now = PUBLISH + 5 * MINUTE
        rig.det.note_publish("t_a", 3, "publish", mode="shadow")
        rig.window(200, 100)
        [result] = rig.tick_at(15 * MINUTE)  # v2's window, ended on time
        assert result.version == 2 and result.outcome is Outcome.ALERTED

    def test_a_shadow_publish_does_not_change_the_rollback_target(self):
        rig = Rig()
        rig.baseline()
        rig.det.note_publish("t_a", 1, "publish")  # v1 is active
        rig.det.note_publish("t_a", 2, "publish", mode="shadow")  # a candidate, deciding nothing
        rig.publish(version=3)  # v3 goes live: the rollback must point at v1, not v2
        rig.window(200, 100)
        rig.tick_at(15 * MINUTE)
        [alert] = rig.alerts.alerts
        assert alert.rollback == "/v1/tenants/t_a/guardrails/versions/1/rollback"

    def test_promoting_the_shadow_candidate_does_start_a_watch(self):
        rig = Rig()
        rig.baseline()
        rig.det.note_publish("t_a", 1, "publish")
        rig.det.note_publish("t_a", 2, "publish", mode="shadow")
        rig.publish(version=2, action="promote")
        rig.window(200, 100)
        rig.tick_at(15 * MINUTE)
        [alert] = rig.alerts.alerts
        assert alert.rollback.endswith("/versions/1/rollback")

    def test_a_shadow_publish_alone_starts_no_watch(self):
        rig = Rig()
        rig.det.note_publish("t_a", 2, "publish", mode="shadow")
        rig.det.note_publish("t_a", 3, "publish", active=False)
        assert rig.det.watching == []

    def test_on_published_reads_the_mode_off_the_event(self):
        from types import SimpleNamespace

        rig = Rig()
        shadow = SimpleNamespace(tenant_id="t_a", version=2, action="publish", mode="shadow")
        enforce = SimpleNamespace(tenant_id="t_a", version=2, action="publish", mode="enforce")
        rig.det.on_published(shadow)
        assert rig.det.watching == []
        rig.det.on_published(enforce)
        assert rig.det.watching == ["t_a"]


class TestIdempotencyKey:
    def alert_from(self, tick_offset: float):
        rig = Rig()
        rig.baseline()
        rig.publish(version=2)
        rig.window(200, 100)
        rig.tick_at(15 * MINUTE + tick_offset)
        [alert] = rig.alerts.alerts
        return alert

    def test_replicas_raise_the_same_key_for_the_same_publish(self):
        a = self.alert_from(tick_offset=0.0)
        b = self.alert_from(tick_offset=17.0)
        assert a.dedupe_key == b.dedupe_key
        assert a.dedupe_key.startswith("bad_publish_block_rate:t_a:2:")

    def test_the_key_follows_the_event_time_not_each_replicas_receive_time(self):
        keys = []
        for received_at in (PUBLISH + 1.0, PUBLISH + 58.0):  # two replicas, a minute apart
            rig = Rig()
            rig.baseline()
            rig.clock.now = received_at
            rig.det.note_publish("t_a", 2, "publish", at=PUBLISH + 0.5)  # the event's own time
            rig.window(200, 100)
            rig.clock.now = PUBLISH + 16 * MINUTE
            rig.det.tick()
            keys.append(rig.alerts.alerts[0].dedupe_key)
        assert keys[0] == keys[1]

    def test_a_different_version_or_tenant_is_a_different_key(self):
        keys = set()
        for version, tenant in ((2, "t_a"), (3, "t_a"), (2, "t_b")):
            rig = Rig()
            rig.baseline(tenant=tenant)
            rig.publish(version=version, tenant=tenant)
            rig.window(200, 100, tenant=tenant)
            rig.tick_at(15 * MINUTE)
            keys.add(rig.alerts.alerts[0].dedupe_key)
        assert len(keys) == 3

    def test_the_durable_sink_stores_replica_duplicates_once(self):
        from guardrail_engine.delivery import DurableAlertSink, InMemoryOutbox

        outbox = InMemoryOutbox()
        sink = DurableAlertSink(outbox)
        for _ in range(3):  # three replicas, one shared outbox
            sink.emit(self.alert_from(tick_offset=0.0))
        assert outbox.stats().pending == 1


class SpyLock:
    """The detector's lock, reporting each release (outside the lock) to a hook."""

    def __init__(self, inner, on_release) -> None:
        self.inner, self.on_release, self.releases = inner, on_release, 0
        self.hooking = False

    def __enter__(self):
        self.inner.acquire()
        return self

    def __exit__(self, *exc):
        self.inner.release()
        self.releases += 1
        if not self.hooking:
            self.hooking = True
            try:
                self.on_release()
            finally:
                self.hooking = False


class TestPruneOffTheCheckPath:
    def test_a_big_prune_gives_the_lock_back_between_chunks(self, monkeypatch):
        import threading

        from guardrail_engine.monitoring import block_rate

        monkeypatch.setattr(block_rate, "_PRUNE_CHUNK", 10)
        rig = Rig()
        for n in range(105):  # 105 tenants with history that will be stale
            rig.traffic(T0, 3, 1, tenant=f"t_{n:03d}")
        rig.clock.now = T0 + 10 * 24 * HOUR  # everything is older than 7 days
        seen = []
        rig.det._lock = SpyLock(
            threading.Lock(),
            lambda: seen.append(rig.det.observe("t_live", Decision.ALLOW, Reason.POLICY)),
        )
        rig.det.tick()
        # A release for the evaluation, one for the platform counters, one per chunk of ten.
        assert len(seen) >= 2 + 11
        assert rig.det._minutes.keys() == {"t_live"} and rig.det._hours.keys() == {"t_live"}
        assert "t_000" not in rig.det._first_seen

    def test_the_first_tick_after_a_long_history_still_prunes_everything_old(self):
        rig = Rig()
        for n in range(50):
            rig.traffic(T0 + n * HOUR, 5, 1, tenant="t_a")
        rig.clock.now = T0 + 30 * 24 * HOUR
        rig.det.tick()
        assert rig.det._minutes == {} and rig.det._hours == {}

    def test_nothing_old_means_no_work(self):
        from guardrail_engine.monitoring.block_rate import _Counts

        counts = _Counts()
        counts.add(100, block=False)
        counts.add(105, block=True)
        counts.prune(100)  # nothing older than 100
        assert counts.oldest == 100 and len(counts.buckets) == 2
        counts.prune(103)
        assert counts.oldest == 105 and list(counts.buckets) == [105]
        counts.prune(200)
        assert counts.oldest is None and counts.buckets == {}
