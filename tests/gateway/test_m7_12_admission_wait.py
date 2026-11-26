"""M7-12 attempt 2: a non-production caller can ask the limiter how long it would be made to wait.

Run 1 of the redaction trial spaced its checks by their average size and lost 45 of 492 to the
consumer's own token allowance: a check larger than the bucket needs a full one, and leaves it in
debt. :meth:`ConsumerAllowances.admission_wait` and :meth:`DecisionGateway.consumer_admission_wait`
say how long the limiter would make a call of a given size wait, without taking anything, so a
harness can wait exactly that long. These tests pin that the answer is the one the limiter acts on.
"""

from datetime import UTC, datetime

import pytest
from test_gateway import close_gateways  # noqa: F401  (an autouse fixture)
from test_gateway_m3_07 import QRig
from test_gateway_m3_10 import PROJECT, estimate_of, text, token_rate_failure

from guardrail_engine.decision import Answered, Failed
from guardrail_engine.gateway import (
    ConsumerAllowances,
    InProcessTokenRateStore,
    QuotaConfig,
    TokenRateConfig,
)
from guardrail_engine.gateway.tenant_quota import QuotaCharge, QuotaRefusal

PROJECT_CONFIG = TokenRateConfig(project_id=PROJECT)
"""Tier 1 at the defaults: a calibration consumer's bucket is 5,230 tokens refilling at 1,046 a
second (a tenth of the project's)."""
CONSUMER = "calibration"


def allowances() -> ConsumerAllowances:
    store = InProcessTokenRateStore()
    return ConsumerAllowances(
        None,
        lambda: store,
        project=PROJECT_CONFIG,
        wall_clock=lambda: datetime(2026, 6, 15, 12, 0, tzinfo=UTC),
    )


def take(a: ConsumerAllowances, tokens: int, now: float) -> QuotaCharge:
    charged = a.charge(tenant_id="t", tier=None, consumer=CONSUMER, tokens=tokens, now=now)
    assert isinstance(charged, QuotaCharge), charged
    return charged


def test_a_full_bucket_admits_at_once_and_the_question_takes_nothing():
    a = allowances()
    assert a.token_capacity(CONSUMER) == 5230
    for _ in range(5):  # asking changes nothing
        assert a.admission_wait(CONSUMER, 5000, now=0.0) == 0.0
    take(a, 5000, 0.0)  # all of it was still there to take


def test_a_spent_bucket_says_how_long_and_waiting_that_long_is_enough():
    a = allowances()
    take(a, 5000, 0.0)
    wait = a.admission_wait(CONSUMER, 3000, now=0.0)
    assert wait == pytest.approx((3000 - (5230.77 - 5000)) / 1046.15, rel=1e-3)
    assert a.admission_wait(CONSUMER, 3000, now=0.0) == wait  # asking again takes nothing
    refused = a.charge(tenant_id="t", tier=None, consumer=CONSUMER, tokens=3000, now=wait * 0.99)
    assert isinstance(refused, QuotaRefusal)  # a little short is refused
    take(a, 3000, wait + 0.01)  # and exactly the wait is enough


def test_a_call_larger_than_the_bucket_waits_for_a_full_one_and_leaves_it_in_debt():
    a = allowances()
    take(a, 4000, 0.0)
    # 14,000 tokens is reserved as the whole bucket: the wait is for it to be full again
    wait = a.admission_wait(CONSUMER, 14_000, now=0.0)
    assert wait == pytest.approx((5230 - (5230.77 - 4000)) / 1046.15, rel=1e-3)
    charge = take(a, 14_000, wait + 0.01)
    assert charge.tokens == 5230
    a.reconcile(charge, 10_000, now=wait + 1.0)  # what it really used: the bucket is in debt
    after = a.admission_wait(CONSUMER, 800, now=wait + 1.0)
    assert after > 4.0  # the next, small check waits for the debt to clear, not for 800 tokens
    take(a, 800, wait + 1.0 + after + 0.01)


def test_the_wait_is_for_the_larger_of_the_tokens_and_the_requests_allowance():
    a = allowances()
    for _ in range(50):  # the requests bucket (150 a minute, 5 s deep) runs out first
        got = a.charge(tenant_id="t", tier=None, consumer=CONSUMER, tokens=1, now=0.0)
        if isinstance(got, QuotaRefusal):
            break
    else:
        raise AssertionError("the requests allowance never ran out")
    assert a.admission_wait(CONSUMER, 1, now=0.0) > 0


def test_production_and_a_limiter_that_is_off_never_wait():
    assert allowances().admission_wait("check", 10**6, now=0.0) == 0.0
    off = ConsumerAllowances(None, InProcessTokenRateStore, project=None, wall_clock=lambda: None)
    assert off.admission_wait(CONSUMER, 10**6, now=0.0) == 0.0
    assert off.token_capacity(CONSUMER) == 0


async def test_the_gateway_answers_with_the_wait_its_own_limiter_acts_on():
    rig = QRig(QuotaConfig(), project=PROJECT_CONFIG)
    refused = None
    for _ in range(80):  # a calibration run's checks until the allowance refuses one
        timed = await rig.check(usage_class=CONSUMER)
        if isinstance(timed.result, Failed):
            refused = timed
            break
    assert refused is not None
    token_rate_failure(refused, "calibration allowance")
    gateway, estimate = rig.gateway, rig.estimate
    wait = gateway.consumer_admission_wait(CONSUMER, estimate)
    assert wait > 0
    assert gateway.consumer_admission_wait(CONSUMER, estimate) == pytest.approx(wait)
    assert gateway.consumer_admission_wait("check", estimate) == 0.0  # production is never held
    rig.vt.advance(wait + 0.01)  # the harness sleeps exactly the wait it was told
    assert gateway.consumer_admission_wait(CONSUMER, estimate) == 0.0
    assert isinstance((await rig.check(usage_class=CONSUMER)).result, Answered)


async def test_a_gateway_without_a_token_rate_limiter_never_asks_anyone_to_wait():
    rig = QRig(None, project=None)
    assert rig.gateway.consumer_admission_wait(CONSUMER, estimate_of(text(0))) == 0.0
