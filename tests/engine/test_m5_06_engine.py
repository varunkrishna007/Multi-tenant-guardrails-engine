"""M5-06 on the engine: a tenant assigned a dedicated Gemini project is served by that project's
key and gateway and no other, standard tenants share the default project, a tenant named for a
project with no backend fails closed, and no key ever shows in a setting, an error or a log."""

import logging

import httpx
import pytest
from engine_fixtures import TENANT, answer_everything, bundle, ctx, directory, settings, verifier

from guardrail_engine.authz import InMemoryAuthzAudit
from guardrail_engine.decision import FakeDecisionModel
from guardrail_engine.engine import EngineSettings, SettingsError, build_engine
from guardrail_engine.gateway import InProcessTokenRateStore, TokenRateConfig
from guardrail_engine.guard import Decision, TenantProfile
from guardrail_engine.policy import TenantAttributes

REG = "t_regulated"
LABEL = "reg-acme"
SHARED_KEY = "SHARED-sentinel-key-0001"
REG_KEY = "REGULATED-sentinel-key-0002"
KEY_ENV = "GEMINI_KEY_REG_ACME"


def project_settings(**extra):
    return settings(
        projects={"dedicated": {LABEL: {"key_env": KEY_ENV}}},
        token_rate={},  # the limiter on, in test, for every project
        **extra,
    )


def profile(tenant_id, *, tier="standard", project=None):
    return TenantProfile.build(
        TenantAttributes(tenant_id=tenant_id, tier=tier, project=project),
        "insurance",
        slug=tenant_id.removeprefix("t_"),
    )


async def build(tenants, **kwargs):
    return await build_engine(
        kwargs.pop("settings", project_settings()),
        verifier=verifier(),
        tenants=tenants,
        authz_audit=InMemoryAuthzAudit(),
        **kwargs,
    )


async def published(models, *profiles, **kwargs):
    """An engine whose tenants were published as standard (bootstrap's rule), then given their
    real profiles: the way a tier raise reaches a live tenant."""
    tenants = directory(*(profile(p.tenant_id) for p in profiles))
    engine = await build(tenants, **models, **kwargs)
    for p in profiles:
        await engine.bootstrap_publish(bundle(p.tenant_id))
        tenants.put(p)
        engine.guard.policy_cache.invalidate(p.tenant_id)
    return engine


async def test_each_tenant_is_served_by_its_own_projects_model():
    shared, dedicated = FakeDecisionModel(), FakeDecisionModel()
    standard = profile(TENANT)
    regulated = profile(REG, tier="regulated", project=LABEL)
    engine = await published(
        {"model": shared, "project_models": {LABEL: dedicated}}, standard, regulated
    )
    try:
        v = verifier()
        assert (await engine.check(ctx(v, REG), "output", "Hello.")).decision is Decision.ALLOW
        assert (len(shared.calls), len(dedicated.calls)) == (0, 1)
        assert (await engine.check(ctx(v, TENANT), "output", "Hello.")).decision is Decision.ALLOW
        assert (len(shared.calls), len(dedicated.calls)) == (1, 1)
    finally:
        await engine.shutdown()


async def test_each_project_has_its_own_gateway_limiter_and_one_shared_store():
    store = InProcessTokenRateStore()
    engine = await published(
        {
            "model": FakeDecisionModel(),
            "project_models": {LABEL: FakeDecisionModel()},
            "rate_store": store,
        },
        profile(REG, tier="regulated", project=LABEL),
    )
    try:
        gateways = engine.guard.gateways
        assert set(gateways) == {None, LABEL}
        limiters = {k: g.token_rate_limiter for k, g in gateways.items()}
        assert limiters[None].project_id == "default" and limiters[LABEL].project_id == LABEL
        assert limiters[None].store is limiters[LABEL].store is store
        assert limiters[None] is not limiters[LABEL]
        assert gateways[None]._key_id() != gateways[LABEL]._key_id()
    finally:
        await engine.shutdown()


async def test_a_project_has_its_own_token_rate_settings():
    own = TokenRateConfig(tier="tier_2", tokens_per_minute=4_000_000)
    s = settings(
        projects={"dedicated": {LABEL: {"key_env": KEY_ENV, "token_rate": own}}},
        token_rate={},
    )
    assert s.effective_project_token_rate(LABEL).tokens_per_minute == 4_000_000
    assert s.effective_project_token_rate(LABEL).project_id == LABEL
    assert s.effective_token_rate().project_id == "default"


async def test_a_tenant_named_for_a_project_with_no_backend_fails_closed_never_shared():
    shared = FakeDecisionModel()
    engine = await published(
        {"model": shared, "project_models": {LABEL: FakeDecisionModel()}},
        profile(REG, tier="regulated", project="ghost"),
    )
    try:
        verdict = await engine.check(ctx(verifier(), REG), "output", "Hello.")
        assert verdict.decision is not Decision.ALLOW
        assert shared.calls == []  # the shared pool was not used to serve it
    finally:
        await engine.shutdown()


async def test_a_dedicated_projects_own_key_is_the_one_sent(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", SHARED_KEY)
    monkeypatch.setenv(KEY_ENV, REG_KEY)
    sent: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request.headers["x-goog-api-key"])
        return answer_everything(request)

    s = settings(
        gemini={"paid_tier": True, "base_url": "http://127.0.0.1:9/v1beta"},
        projects={"dedicated": {LABEL: {"key_env": KEY_ENV}}},
    )
    tenants = directory(profile(TENANT), profile(REG))
    async with (
        httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client,
        await build(tenants, settings=s, http_client=client) as engine,
    ):
        await engine.bootstrap_publish(bundle(TENANT))
        await engine.bootstrap_publish(bundle(REG))
        tenants.put(profile(REG, tier="regulated", project=LABEL))
        engine.guard.policy_cache.invalidate(REG)
        v = verifier()
        await engine.check(ctx(v, REG), "output", "Hello.")
        await engine.check(ctx(v, TENANT), "output", "Hello.")
        keys = {label: g._key_id() for label, g in engine.guard.gateways.items()}  # fingerprints
    assert sent == [REG_KEY, SHARED_KEY]
    assert all(SHARED_KEY not in k and REG_KEY not in k for k in keys.values())


# ------------------------------------------------------------ startup, and never a secret


async def test_a_project_with_neither_a_model_nor_its_key_variable_stops_startup(monkeypatch):
    monkeypatch.delenv(KEY_ENV, raising=False)
    with pytest.raises(SettingsError) as raised:
        await build(directory(), settings=project_settings(), model=FakeDecisionModel())
    assert f"projects.dedicated.{LABEL}.key_env" in str(raised.value)
    assert f"{KEY_ENV} is not set" in str(raised.value)


async def test_a_bad_key_in_the_variable_is_refused_without_repeating_it(monkeypatch):
    bad = "has a newline\n-sentinel-REG-KEY"
    monkeypatch.setenv(KEY_ENV, bad)
    with pytest.raises(SettingsError) as raised:
        await build(directory(), settings=project_settings(), model=FakeDecisionModel())
    assert "sentinel-REG-KEY" not in str(raised.value) and "refused" in str(raised.value)


async def test_a_model_for_an_unknown_project_is_refused():
    with pytest.raises(SettingsError, match="not a dedicated project"):
        await build(
            directory(),
            model=FakeDecisionModel(),
            project_models={LABEL: FakeDecisionModel(), "other": FakeDecisionModel()},
        )


@pytest.mark.parametrize(
    "dedicated",
    [
        {"AIzaSyD-example": {"key_env": KEY_ENV}},  # a label that is not a label
        {"default": {"key_env": KEY_ENV}},  # the shared pool's own label
        {LABEL: {"key_env": "AIzaSyDexample0123456789"}},  # a key where a name belongs
        {LABEL: {"key_env": "GEMINI_API_KEY"}},  # the shared pool's variable
        {LABEL: {"key_env": KEY_ENV}, "reg-two": {"key_env": KEY_ENV}},  # one key for two
        {LABEL: {"key_env": KEY_ENV, "api_key": "x"}},  # no key field exists
    ],
)
def test_the_projects_setting_holds_names_never_keys(dedicated):
    with pytest.raises(SettingsError) as raised:
        EngineSettings.from_mapping({"projects": {"dedicated": dedicated}})
    for secret in ("AIzaSyDexample0123456789", "AIzaSyD-example"):
        assert secret not in str(raised.value)


def test_a_project_label_and_its_variable_name_are_not_secrets():
    s = EngineSettings.from_mapping({"projects": {"dedicated": {LABEL: {"key_env": KEY_ENV}}}})
    assert s.dedicated_project_labels() == (LABEL,)
    assert KEY_ENV in repr(s) and s.projects.dedicated[LABEL].key_env == KEY_ENV


async def test_no_key_reaches_a_log_line_or_the_engines_repr(monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    monkeypatch.setenv("GEMINI_API_KEY", SHARED_KEY)
    monkeypatch.setenv(KEY_ENV, REG_KEY)
    s = settings(
        gemini={"paid_tier": True, "base_url": "http://127.0.0.1:9/v1beta"},
        projects={"dedicated": {LABEL: {"key_env": KEY_ENV}}},
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(answer_everything)) as client:
        engine = await build(directory(), settings=s, http_client=client)
        shown = repr(engine) + repr(engine.guard.gateways) + repr(s)
        await engine.shutdown()
    assert REG_KEY not in shown + caplog.text and SHARED_KEY not in shown + caplog.text
