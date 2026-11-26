"""M7-10: ``DecisionGateway.wrap_model`` sees every provider send, a breaker probe included, so a
cap on the requests a process sends counts them all."""

from test_gateway import Harness

from guardrail_engine.decision import FailureKind
from guardrail_engine.decision.capped import CallCap, CappedDecisionModel


async def test_a_breaker_probe_is_a_send_and_is_counted_and_capped():
    h = Harness()
    cap = CallCap(2)
    h.gateway.wrap_model(lambda model: CappedDecisionModel(model, cap))
    await h.open_breaker()  # the auth failure was the first send
    assert cap.used == 1
    h.vt.advance(5.0)
    await h.decide()  # the probe is the second
    assert cap.used == 2
    h.vt.advance(60.0)
    refused = await h.decide()  # a probe past the cap sends nothing
    assert cap.used == 2 and refused.kind in (FailureKind.OTHER, FailureKind.AUTH)


async def test_a_retry_is_a_send_too():
    h = Harness()
    cap = CallCap(3)
    h.gateway.wrap_model(lambda model: CappedDecisionModel(model, cap))
    h.fake.fail_next(FailureKind.UNAVAILABLE, 1)
    assert not isinstance(await h.decide(), type(None))
    assert cap.used == 2  # the first send and its retry
