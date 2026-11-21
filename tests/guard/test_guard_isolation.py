"""M1-05 AC-T2: with interleaved tenants, no ``decide`` call ever holds content or questions
from more than one tenant (design §Multi-tenancy: one call per tenant, guard point and
chunk; no cross-tenant batching)."""

import asyncio
import re

from guard_fixtures import ALPHA, BETA, GAMMA, Env, bundle, rule
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from guardrail_engine.gateway import GatewayConfig
from guardrail_engine.guard import GuardConfig, Plan, ToolResult, Turn
from guardrail_engine.policy import GUARD_POINTS

TENANTS = {ALPHA: "insurance", BETA: "energy", GAMMA: "finance"}
MARKER = re.compile(r"\[\[(t_[a-z]+)#\d+\]\]")
TEXT = st.text(alphabet="abcdefghij klmnopqrstuvwxyz.,!?\n", max_size=40)
MAX_REQUESTS = 24
# The property is about calls interleaving at the model, so every check of a burst must
# reach it concurrently. The gateway's per-key admission limit (default 2, M1-04) would
# serialise the burst and refuse most of it under the default budgets; this test lifts it
# to the burst size. Admission control has its own tests (tests/gateway).
ALL_AT_ONCE = GatewayConfig(max_in_flight_per_key=MAX_REQUESTS)


def tenant_bundle(tenant_id: str):
    name = tenant_id.removeprefix("t_")
    return bundle(
        tenant_id,
        rules=[
            rule(
                f"{name}_rule",
                gps=GUARD_POINTS,
                question=f"Does the content break the [[{tenant_id}#0]] house rule?",
            )
        ],
    )


request_strategy = st.tuples(
    st.sampled_from(sorted(TENANTS)),
    st.sampled_from(GUARD_POINTS),
    TEXT,
    st.lists(st.sampled_from(["turn", "plan", "tool"]), max_size=3),
    st.floats(min_value=0, max_value=0.003),
)


@settings(
    max_examples=40,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
@given(requests=st.lists(request_strategy, min_size=2, max_size=MAX_REQUESTS))
async def test_ac_t2_no_decide_call_mixes_tenants(requests):
    async with Env(config=GuardConfig(pointer_ttl_s=0.0, gateway=ALL_AT_ONCE)) as env:
        for tenant_id in TENANTS:
            await env.publish(tenant_bundle(tenant_id))

        def build(i, tenant_id, guard_point, text, context_kinds):
            mark = f"[[{tenant_id}#{i + 1}]]"
            context = []
            for kind in context_kinds:
                if kind == "turn":
                    context.append(Turn("user", f"{mark} earlier turn"))
                elif kind == "plan":
                    context.append(Plan(f'{{"note": "{mark}"}}'))
                else:
                    context.append(ToolResult("cms.search", f"{mark} result"))
            return env.service.check(
                env.ctx(tenant_id, conversation=tuple(context)),
                guard_point,
                f"{mark} {text} {mark}",
            )

        for *_, latency in requests:
            env.fake.slow_next(latency)
        verdicts = await asyncio.gather(
            *(build(i, t, gp, text, kinds) for i, (t, gp, text, kinds, _) in enumerate(requests))
        )

    assert [v.tenant_id for v in verdicts] == [r[0] for r in requests]
    assert len(env.fake.calls) == len(requests)
    seen_inputs = set()
    for call in env.fake.calls:
        in_input = set(MARKER.findall(call.input))
        in_questions = {
            m for q in call.questions.values() for m in MARKER.findall(q.model_dump_json())
        }
        tenant_keys = {k for k in call.questions if k.startswith("t__")}
        assert len(in_input) == 1, call.input
        [owner] = in_input
        assert in_questions == {owner}
        assert tenant_keys == {f"t__{owner.removeprefix('t_')}_rule"}
        domains = re.findall(r"^TENANT DOMAIN: (.*)$", call.input, flags=re.MULTILINE)
        assert domains == [TENANTS[owner]]
        seen_inputs.add(call.input)
    assert len(seen_inputs) == len(requests)  # every check got its own call
