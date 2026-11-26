"""M1 integration: the factory's two test-only overrides (M1-14).

* ``pii_detector`` is passed through to the Guard Service, accepted **only** in ``test``.
* ``nonce_source`` is passed through to the renderer, accepted **only** in ``test``.

Both are refused at build time (nothing is started) and their use is recorded: on
``Engine.test_overrides``, in a WARNING line when the engine is built, and on every bootstrap
publish's class A event.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Sequence

import pytest
from engine_fixtures import bundle, ctx, directory, settings, verifier

from guardrail_engine.decision import FakeDecisionModel
from guardrail_engine.engine import SettingsError, build_engine
from guardrail_engine.engine.bootstrap import ADMIN_AUDIT_LOGGER
from guardrail_engine.guard import Decision, Reason
from guardrail_engine.guard.pii import PiiKind, PiiMatch

NONCE = "0123456789abcdef0123456789abcdef"
MARKER = "zebra-crossing"


class MarkerDetector:
    """Finds the word ``zebra-crossing`` as a phone number: something the deterministic
    detector would never redact, so a redacted marker proves this detector ran."""

    def __init__(self) -> None:
        self.texts: list[str] = []

    def find(self, text: str) -> Sequence[PiiMatch]:
        self.texts.append(text)
        start = text.find(MARKER)
        if start < 0:
            return ()
        return (PiiMatch(PiiKind.PHONE, start, start + len(MARKER)),)


def fixed_nonce() -> str:
    return NONCE


# ---------------------------------------------------------------------- pii_detector


async def test_a_pii_detector_override_reaches_the_guard_service():
    fake, detector, v = FakeDecisionModel(), MarkerDetector(), verifier()
    async with await build_engine(
        settings(), verifier=v, tenants=directory(), model=fake, pii_detector=detector
    ) as engine:
        await engine.bootstrap_publish(bundle())
        verdict = await engine.check(ctx(v), "output", f"meet at the {MARKER} at noon")
    assert verdict.decision is Decision.ALLOW and verdict.reason is Reason.POLICY
    assert detector.texts  # the override, not the default, was asked
    assert MARKER not in fake.calls[0].input
    assert "[PHONE]" in fake.calls[0].input
    assert verdict.pii_redacted == {PiiKind.PHONE: 1}


async def test_without_an_override_the_default_detector_is_used():
    fake, v = FakeDecisionModel(), verifier()
    async with await build_engine(
        settings(), verifier=v, tenants=directory(), model=fake
    ) as engine:
        assert engine.test_overrides == ()
        await engine.bootstrap_publish(bundle())
        await engine.check(ctx(v), "output", f"meet at the {MARKER} at noon")
    assert MARKER in fake.calls[0].input  # the deterministic detector leaves it alone


async def test_a_pii_detector_override_is_accepted_in_test():
    engine = await build_engine(
        settings("test"),
        verifier=verifier(),
        tenants=directory(),
        model=FakeDecisionModel(),
        pii_detector=MarkerDetector(),
    )
    try:
        assert engine.test_overrides == ("pii_detector",)
    finally:
        await engine.shutdown()


@pytest.mark.parametrize("environment", ["production", "staging"])
async def test_a_pii_detector_override_is_refused_outside_test(environment):
    fake = FakeDecisionModel()
    with pytest.raises(SettingsError) as raised:
        await build_engine(
            settings(environment),
            verifier=verifier(),
            tenants=directory(),
            model=fake,
            pii_detector=MarkerDetector(),
        )
    assert "pii_detector" in str(raised.value)
    assert environment in str(raised.value)
    assert fake.calls == []


async def test_production_with_no_detector_override_still_builds():
    engine = await build_engine(
        settings("production"), verifier=verifier(), tenants=directory(), model=FakeDecisionModel()
    )
    await engine.shutdown()
    assert engine.test_overrides == ()


# ---------------------------------------------------------------------- nonce_source


async def test_a_nonce_source_reaches_the_renderer_in_test():
    fake, v = FakeDecisionModel(), verifier()
    async with await build_engine(
        settings("test"), verifier=v, tenants=directory(), model=fake, nonce_source=fixed_nonce
    ) as engine:
        assert engine.test_overrides == ("nonce_source",)
        await engine.bootstrap_publish(bundle())
        first = await engine.check(ctx(v), "output", "What does my policy cover?")
        second = await engine.check(ctx(v), "output", "What does my policy cover?")
    assert first.decision is Decision.ALLOW and second.decision is Decision.ALLOW
    assert NONCE in fake.calls[0].input
    # Reproducible: the same request renders byte for byte the same with the same source.
    assert fake.calls[0].input == fake.calls[1].input


async def test_without_a_nonce_source_each_check_draws_a_fresh_nonce():
    fake, v = FakeDecisionModel(), verifier()
    async with await build_engine(
        settings("test"), verifier=v, tenants=directory(), model=fake
    ) as engine:
        await engine.bootstrap_publish(bundle())
        for _ in range(2):
            await engine.check(ctx(v), "output", "What does my policy cover?")
    assert NONCE not in fake.calls[0].input
    assert fake.calls[0].input != fake.calls[1].input


@pytest.mark.parametrize("environment", ["staging", "production"])
async def test_a_nonce_source_is_refused_outside_test(environment):
    fake = FakeDecisionModel()
    with pytest.raises(SettingsError) as raised:
        await build_engine(
            settings(environment),
            verifier=verifier(),
            tenants=directory(),
            model=fake,
            nonce_source=fixed_nonce,
        )
    message = str(raised.value)
    assert "nonce_source" in message and repr(environment) in message
    assert NONCE not in message
    assert fake.calls == []


async def test_a_nonce_source_that_isnt_callable_is_refused():
    with pytest.raises(SettingsError, match="nonce_source"):
        await build_engine(
            settings("test"),
            verifier=verifier(),
            tenants=directory(),
            model=FakeDecisionModel(),
            nonce_source=NONCE,  # type: ignore[arg-type]
        )


async def test_both_overrides_are_refused_together_in_production():
    with pytest.raises(SettingsError) as raised:
        await build_engine(
            settings("production"),
            verifier=verifier(),
            tenants=directory(),
            model=FakeDecisionModel(),
            pii_detector=MarkerDetector(),
            nonce_source=fixed_nonce,
        )
    assert "nonce_source" in str(raised.value) and "pii_detector" in str(raised.value)


# ---------------------------------------------------------------------- recording


async def test_override_use_is_logged_when_the_engine_is_built(caplog):
    caplog.set_level(logging.INFO, logger="guardrail_engine.engine.factory")
    engine = await build_engine(
        settings("test"),
        verifier=verifier(),
        tenants=directory(),
        model=FakeDecisionModel(),
        pii_detector=MarkerDetector(),
        nonce_source=fixed_nonce,
    )
    await engine.shutdown()
    assert engine.test_overrides == ("nonce_source", "pii_detector")
    warnings = [
        r.getMessage()
        for r in caplog.records
        if r.levelno == logging.WARNING and "test-only overrides" in r.getMessage()
    ]
    assert warnings == ["engine built with test-only overrides: nonce_source, pii_detector "
                        "(environment=test)"]  # fmt: skip
    assert all(NONCE not in r.getMessage() for r in caplog.records)


async def test_no_override_logs_no_warning(caplog):
    caplog.set_level(logging.INFO, logger="guardrail_engine.engine.factory")
    engine = await build_engine(
        settings("test"), verifier=verifier(), tenants=directory(), model=FakeDecisionModel()
    )
    await engine.shutdown()
    assert not any("test-only overrides" in r.getMessage() for r in caplog.records)


async def test_override_use_is_on_the_bootstrap_class_a_event(caplog):
    caplog.set_level(logging.INFO, logger=ADMIN_AUDIT_LOGGER)
    async with await build_engine(
        settings("test"),
        verifier=verifier(),
        tenants=directory(),
        model=FakeDecisionModel(),
        nonce_source=fixed_nonce,
    ) as engine:
        await engine.bootstrap_publish(bundle())
    [record] = [r for r in caplog.records if r.name == ADMIN_AUDIT_LOGGER]
    event = json.loads(record.getMessage().split(" ", 4)[-1])
    assert event["test_overrides"] == ["nonce_source"]
    assert event["schema_version"] == 2
