"""M7-11 on the engine: the provider-health settings reach the gateways, the measurement
harnesses turn the breaker off, and a real engine fails checks at once during an outage."""

import pytest
from engine_fixtures import TENANT, ctx, directory, settings, verifier

from guardrail_engine.decision import FailureKind, FakeDecisionModel
from guardrail_engine.engine import EngineSettings, SettingsError, build_engine
from guardrail_engine.guard import Decision, Reason


def test_the_defaults_are_five_in_a_row_or_half_of_twenty_in_thirty_seconds():
    gateway = EngineSettings().gateway
    assert (gateway.degraded_consecutive, gateway.degraded_window_calls) == (5, 20)
    assert gateway.degraded_window_s == 30.0


def test_the_settings_are_checked():
    for bad in (
        {"degraded_consecutive": -1},
        {"degraded_window_calls": 2.5},
        {"degraded_window_s": 0},
        {"degraded_window_s": float("inf")},
    ):
        with pytest.raises(SettingsError):
            settings("test", gateway=bad)
    settings("test", gateway={"degraded_consecutive": 0, "degraded_window_calls": 0})


def test_the_measurement_harnesses_turn_the_breaker_off():
    """They measure the model and the gateway's own limits; failing the later checks at once
    after a few failed calls would measure the breaker instead."""
    from calibration.engine_path import settings_mapping

    for live in (False, True):
        gateway = EngineSettings.from_mapping(settings_mapping(2, live=live)).gateway
        assert (gateway.degraded_consecutive, gateway.degraded_window_calls) == (0, 0)


async def test_a_real_engine_fails_checks_at_once_during_an_outage_and_recovers():
    model = FakeDecisionModel()
    engine = await build_engine(
        settings("test"), verifier=verifier(), tenants=directory(), model=model
    )
    try:
        assert engine.provider_health_service is not None  # the operator's route has a service
        await engine.bootstrap_publish(
            {
                "schema_version": 1,
                "tenant_id": TENANT,
                "version": 1,
                "extends": ["platform/floor@1"],
            }
        )
        model.fail_next(FailureKind.UNAVAILABLE, 5)
        for _ in range(3):  # two calls each (the gateway's one retry): the fifth opens it
            await engine.check(ctx(verifier()), "input", "hello")
        calls = len(model.calls)
        v = await engine.check(ctx(verifier()), "input", "hello again")
        assert v.degraded is True and v.decision is Decision.BLOCK
        assert v.reason is Reason.MODEL_FAILURE and v.retryable and v.provider_calls == 0
        assert len(model.calls) == calls
        engine.gateway.force_degraded(False)  # an operator lifts it
        assert (await engine.check(ctx(verifier()), "input", "hello once more")).degraded is False
    finally:
        await engine.shutdown()
