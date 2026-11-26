"""M1-11: the settings object. One home per platform setting, defaults read from the
component that owns them, and startup validation that names the bad setting."""

from __future__ import annotations

import dataclasses
import json

import pytest
from engine_fixtures import FLOOR_FILE, adapter_settings, directory, settings, verifier
from pydantic import ValidationError

from guardrail_engine.decision import FakeDecisionModel
from guardrail_engine.decision.adapters.gemini import GeminiConfig
from guardrail_engine.deterministic import NoOtherTenantIdentifiers
from guardrail_engine.engine import (
    DEFAULT_FLOOR_FILE,
    NEXT_FLOOR_FILE,
    EngineSettings,
    GeminiSettings,
    SettingsError,
    build_engine,
)
from guardrail_engine.gateway import GatewayConfig
from guardrail_engine.gateway.gateway import DEFAULT_MAX_IN_FLIGHT_PER_KEY
from guardrail_engine.guard import GuardConfig
from guardrail_engine.policy import PlatformSettings

SENTINEL = "SENTINEL-key-0123456789-do-not-leak"


def gemini_defaults() -> dict:
    return {
        f.name: f.default
        for f in dataclasses.fields(GeminiConfig)
        if f.default is not dataclasses.MISSING
    }


# ---------------------------------------------------------------------- one home, one default


class TestOneHomePerSetting:
    def test_sections_default_to_the_components_own_defaults(self):
        s = EngineSettings()
        assert s.platform == PlatformSettings()
        assert s.gateway == GatewayConfig()
        assert s.guard.pointer_ttl_s == GuardConfig().pointer_ttl_s
        assert s.guard.store_timeout_s == GuardConfig().store_timeout_s
        gemini = s.gemini.model_dump()
        assert gemini == {k: gemini_defaults()[k] for k in gemini}
        assert s.catalog.floor_files == (DEFAULT_FLOOR_FILE, NEXT_FLOOR_FILE)
        assert s.store.kind == "memory"

    def test_documented_defaults(self):
        """The values the decisions set, reached through the settings object."""
        s = EngineSettings()
        assert s.platform.floor_fail_mode == "closed"  # B1
        assert s.platform.question_budgets.output == 50  # R6.1
        assert s.platform.question_budgets.input == 200
        assert s.gateway.budget_cap_s == 3.0  # R6.3 after U7
        assert s.gateway.input_budget_cap_s == 4.0
        assert s.gateway.budget_margin_s == 0.4
        assert s.shutdown.drain_timeout_s == 5.0  # covers the 4 s input cap plus the grace
        # M1-04 / R6.3: the gateway's own default, never restated here. (It was decided to go
        # from 2 to 4; that change belongs to the gateway story, M1-15, and lands here alone.)
        assert s.gateway.max_in_flight_per_key == DEFAULT_MAX_IN_FLIGHT_PER_KEY
        assert s.gateway.max_queued_per_key == 64
        assert s.gemini.keepalive_expiry_s == 60.0  # M1-10
        assert s.gemini.paid_tier is False  # must be declared
        assert s.environment == "production"  # bootstrap_publish must be opted into

    def test_defaults_are_read_from_the_owner_not_copied(self):
        """The settings' defaults are the owners' default objects themselves, not equal
        copies: one source of truth (a copied literal would be a different float object)."""
        from guardrail_engine.decision.adapters import gemini
        from guardrail_engine.guard import policy_cache

        assert GeminiSettings().keepalive_expiry_s is gemini.DEFAULT_KEEPALIVE_EXPIRY_S
        assert GeminiSettings().model is gemini.DEFAULT_MODEL
        assert GeminiSettings().base_url is gemini.DEFAULT_BASE_URL
        guard = EngineSettings().guard
        assert guard.pointer_ttl_s is policy_cache.DEFAULT_POINTER_TTL_S
        assert guard.store_timeout_s is policy_cache.DEFAULT_STORE_TIMEOUT_S

    def test_no_setting_appears_twice(self):
        """The pool size is not a setting (it is the admission limit), and no field name is
        repeated across sections, except where the owner's types already share one."""
        assert "max_in_flight" not in GeminiSettings.model_fields
        assert "max_in_flight_per_key" not in GeminiSettings.model_fields
        assert "gateway" not in type(EngineSettings().guard).model_fields
        assert not any("key" in name for name in GeminiSettings.model_fields)

    def test_no_secret_has_a_home_in_the_settings(self):
        def names(model) -> set[str]:
            found = set()
            for name in type(model).model_fields:
                found.add(name)
                value = getattr(model, name)
                if hasattr(type(value), "model_fields"):
                    found |= names(value)
                elif dataclasses.is_dataclass(value):
                    found |= {f.name for f in dataclasses.fields(value)}
            return found

        assert not [n for n in names(EngineSettings()) if "api_key" in n or "dsn" in n]


# ---------------------------------------------------------------------- loading


class TestLoading:
    def test_toml_file(self, tmp_path):
        path = tmp_path / "engine.toml"
        path.write_text(
            "[gateway]\nmax_in_flight_per_key = 4\n\n"
            "[platform]\nfloor_fail_mode = 'closed'\n\n"
            "[platform.question_budgets]\noutput = 40\n\n"
            "[gemini]\npaid_tier = true\nkeepalive_expiry_s = 30.0\n"
        )
        s = EngineSettings.from_file(path)
        assert s.gateway.max_in_flight_per_key == 4
        assert s.platform.question_budgets.output == 40
        assert s.gemini.paid_tier is True
        assert s.gemini.keepalive_expiry_s == 30.0
        assert s.gateway.max_queued_per_key == 64  # untouched: still the default

    def test_json_file(self, tmp_path):
        path = tmp_path / "engine.json"
        path.write_text(json.dumps({"gateway": {"budgets_s": {"input": 1.2}}}))
        assert EngineSettings.from_file(path).gateway.budgets_s == {"input": 1.2}

    def test_unknown_setting_is_named(self):
        with pytest.raises(SettingsError, match=r"gateway\.max_in_flight\b"):
            EngineSettings.from_mapping({"gateway": {"max_in_flight": 3}})

    @pytest.mark.parametrize(
        "data",
        [
            {"api_key": SENTINEL},
            {"gemini": {"api_key": SENTINEL}},
            {"gemini": {"gemini_api_key": SENTINEL}},
            {"store": {"dsn": SENTINEL}},
            {"gateway": {"api_key": SENTINEL}},
        ],
    )
    def test_a_secret_in_the_settings_is_refused_without_repeating_it(self, data):
        with pytest.raises(SettingsError) as raised:
            EngineSettings.from_mapping(data)
        message = str(raised.value)
        assert "environment" in message and "not a setting" in message
        assert SENTINEL not in message and SENTINEL not in repr(raised.value)
        assert raised.value.__cause__ is None and raised.value.__context__ is None

    def test_a_key_in_a_settings_file_is_refused(self, tmp_path):
        path = tmp_path / "engine.toml"
        path.write_text(f"[gemini]\npaid_tier = true\napi_key = '{SENTINEL}'\n")
        with pytest.raises(SettingsError, match=r"gemini\.api_key: not a setting") as raised:
            EngineSettings.from_file(path)
        assert SENTINEL not in str(raised.value)

    def test_a_value_is_never_repeated_in_a_type_error(self):
        with pytest.raises(SettingsError) as raised:
            EngineSettings.from_mapping({"gateway": {"budget_cap_s": SENTINEL}})
        assert "gateway.budget_cap_s" in str(raised.value)
        assert SENTINEL not in str(raised.value)

    def test_settings_built_in_code_do_not_repeat_values_in_errors(self):
        """Even the raw pydantic error, for settings built directly, hides its input."""
        with pytest.raises(ValidationError) as raised:
            EngineSettings.model_validate({"gemini": {"api_key": SENTINEL, "model": 7}})
        assert SENTINEL not in str(raised.value) and SENTINEL not in repr(raised.value)

    def test_unparseable_file_does_not_quote_it(self, tmp_path):
        path = tmp_path / "engine.toml"
        path.write_text(f"[gemini\napi_key = {SENTINEL}\n")
        with pytest.raises(SettingsError, match="not valid") as raised:
            EngineSettings.from_file(path)
        assert SENTINEL not in str(raised.value)

    def test_other_file_types_are_refused(self, tmp_path):
        with pytest.raises(SettingsError, match=r"\.toml or \.json"):
            EngineSettings.from_file(tmp_path / "engine.yaml")


# ---------------------------------------------------------------------- startup validation


def problems_of(**sections) -> str:
    with pytest.raises(SettingsError) as raised:
        settings(**sections)
    return str(raised.value)


class TestStartupValidation:
    """Each criterion's settings: a bad value refuses to start and names the setting."""

    async def test_paid_tier_must_be_declared_to_build_the_adapter(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", SENTINEL)
        with pytest.raises(SettingsError, match=r"gemini\.paid_tier: must be true") as raised:
            await build_engine(settings(), verifier=verifier())
        assert SENTINEL not in str(raised.value)

    async def test_paid_tier_is_not_needed_with_a_model_override(self):
        engine = await build_engine(settings(), verifier=verifier(), model=FakeDecisionModel())
        await engine.shutdown()

    @pytest.mark.parametrize(
        ("gateway", "named"),
        [
            ({"budget_cap_s": 0.2}, "gateway.budget_cap_s"),
            ({"budget_cap_s": 0}, "gateway: budget_cap_s must be > 0"),
            ({"budget_cap_s": float("inf")}, "gateway.budget_cap_s: Input should be a finite"),
            ({"budget_margin_s": -0.1}, "gateway: budget_margin_s must be >= 0"),
            ({"input_budget_cap_s": 0.2}, "gateway.input_budget_cap_s"),
            ({"input_budget_cap_s": float("inf")}, "gateway.input_budget_cap_s: Input should be"),
            ({"time_window_allowance_s": float("nan")}, "gateway.time_window_allowance_s"),
            ({"budget_margin_fraction": float("inf")}, "gateway.budget_margin_fraction"),
            # M1-15: GatewayConfig itself refuses an override out of bounds.
            ({"default_budget_s": 0.1}, "gateway: default_budget_s (0.1 s) is not more than"),
            ({"budgets_s": {"ouptut": 1.0}}, "gateway.budgets_s: 'ouptut' is not a guard point"),
            ({"budgets_s": {"output": 0.1}}, "gateway: budgets_s['output'] (0.1 s) is not more"),
            ({"budgets_s": {"output": 10.5}}, "above the 10.0 s limit"),
            ({"queue_waits_s": {"ouptut": 0.1}}, "gateway.queue_waits_s: 'ouptut' is not a guard"),
            ({"latency_per_question_s": float("nan")}, "gateway"),
            ({"latency_bands": [[4000, 0.2], [1000, 0.3]]}, "gateway: latency_bands"),
        ],
    )
    def test_budgets(self, gateway, named):
        assert named in problems_of(gateway=gateway)

    @pytest.mark.parametrize(
        ("budgets", "named"),
        [
            ({"output": 0}, "platform.question_budgets.output"),
            ({"input": 1001}, "platform.question_budgets.input: must be at most 1000"),
        ],
    )
    def test_question_budgets(self, budgets, named):
        assert named in problems_of(platform={"question_budgets": budgets})

    async def test_question_budget_smaller_than_the_floor_refuses_to_start(self):
        s = settings(platform={"question_budgets": {"input": 1}})
        with pytest.raises(SettingsError, match=r"platform\.question_budgets\.input: 1 is less"):
            await build_engine(s, verifier=verifier(), model=FakeDecisionModel())

    @pytest.mark.parametrize(
        ("gateway", "named"),
        [
            ({"max_in_flight_per_key": 0}, "max_in_flight_per_key must be >= 1"),
            ({"max_in_flight_per_key": 1.5}, "gateway.max_in_flight_per_key"),
            ({"max_queued_per_key": 0}, "max_queued_per_key must be >= 1"),
        ],
    )
    def test_m1_04_admission_limit_and_queue(self, gateway, named):
        assert named in problems_of(gateway=gateway)

    @pytest.mark.parametrize("value", ["sometimes", "", "CLOSED"])
    def test_b1_floor_fail_mode(self, value):
        message = problems_of(platform={"floor_fail_mode": value})
        assert "platform.floor_fail_mode: must be one of ['closed', 'open']" in message

    def test_b1_open_floor_is_a_legal_setting(self):
        assert settings(platform={"floor_fail_mode": "open"}).platform.floor_fail_mode == "open"

    @pytest.mark.parametrize("value", [0, -1, float("inf"), "soon"])
    def test_m1_10_keepalive(self, value):
        assert "gemini.keepalive_expiry_s" in problems_of(gemini={"keepalive_expiry_s": value})

    @pytest.mark.parametrize("value", [-1, 61])
    def test_pf_13_pointer_ttl(self, value):
        assert "guard.pointer_ttl_s" in problems_of(guard={"pointer_ttl_s": value})

    def test_drain_timeout_must_cover_the_largest_budget(self):
        message = problems_of(shutdown={"drain_timeout_s": 3.5})
        assert "shutdown.drain_timeout_s: 3.5 s is less than" in message
        # The 4 s input cap (R6.3 after U7), the grace, and 3 x 0.25 s policy lookups
        assert "4.760 s" in message
        # an input override above both caps counts too
        message = problems_of(
            gateway={"budgets_s": {"input": 6.0}}, shutdown={"drain_timeout_s": 5.0}
        )
        assert "6.760 s" in message

    def test_drain_timeout_counts_the_policy_lookups_before_the_gateway(self):
        """The default 5 s drain covers 4.76 s. A store timeout raised to 0.5 s needs 5.51 s:
        refused, though the budget plus the grace alone (4.01 s) would fit."""
        assert settings().shutdown.drain_timeout_s >= 4.76
        message = problems_of(guard={"store_timeout_s": 0.5})
        assert "shutdown.drain_timeout_s: 5.0 s is less than" in message
        assert "3 policy lookups at guard.store_timeout_s (5.510 s)" in message
        ok = settings(guard={"store_timeout_s": 0.5}, shutdown={"drain_timeout_s": 5.51})
        assert ok.guard.store_timeout_s == 0.5

    def test_base_url_must_be_https_except_on_loopback(self):
        assert "gemini.base_url" in problems_of(gemini={"base_url": "http://example.com/v1"})
        assert settings(gemini={"base_url": "http://127.0.0.1:8080/v1"})

    @pytest.mark.parametrize(
        "url",
        [
            f"https://user:{SENTINEL}@generativelanguage.googleapis.com/v1beta",
            f"https://{SENTINEL}@generativelanguage.googleapis.com/v1beta",
            f"https://{SENTINEL}:x@127.0.0.1:8080/v1",
            f"http://{SENTINEL}@127.0.0.1:8080/v1",
            f"https://user:{SENTINEL}@[::1]/v1",
        ],
    )
    def test_base_url_with_user_information_is_refused_without_echoing_it(self, url):
        message = problems_of(gemini={"base_url": url})
        assert "gemini.base_url: must not carry user information" in message
        assert SENTINEL not in message

    def test_an_at_sign_after_the_host_is_not_user_information(self):
        s = settings(gemini={"base_url": "https://example.com/v1beta/models/@latest?a=b@c"})
        assert s.gemini.base_url.endswith("b@c")

    @pytest.mark.parametrize(
        "url",
        [f"https://example.com/{SENTINEL}\n", "https://example.com/v 1", "https://exämple.com/v1"],
    )
    def test_base_url_must_be_printable_ascii_without_spaces(self, url):
        message = problems_of(gemini={"base_url": url})
        assert "gemini.base_url: must be printable ASCII" in message
        assert SENTINEL not in message

    @pytest.mark.parametrize(
        "model",
        [
            SENTINEL,  # a pasted key: upper case
            "AIzaSyD-not-a-real-key-0000000000000000",
            "gemini decision",
            "gemini-decision-1\n",
            "-leading-dash",
            "a" * 65,
            "gémini",
        ],
    )
    def test_model_must_be_a_model_id_and_is_not_echoed(self, model):
        message = problems_of(gemini={"model": model})
        assert "gemini.model: must be a model id" in message
        assert model not in message and SENTINEL not in message

    @pytest.mark.parametrize(
        "model", ["models/gemini-decision-1", f"models/{SENTINEL}", "models/x y"]
    )
    def test_a_models_prefix_is_refused_with_advice_to_drop_it(self, model):
        """Decided 2026-11-17: the error says to drop the prefix, without echoing the value."""
        message = problems_of(gemini={"model": model})
        assert "gemini.model: drop the 'models/' prefix" in message
        assert model not in message and SENTINEL not in message

    @pytest.mark.parametrize("model", ["gemini-decision-1", "gemini-2.5-flash", "a", "a" * 64])
    def test_model_ids_are_accepted(self, model):
        assert settings(gemini={"model": model}).gemini.model == model

    def test_model_id_is_checked_for_settings_built_in_code(self):
        s = EngineSettings(gemini=GeminiSettings(model=SENTINEL))
        problems = s.problems()
        assert any(p.startswith("gemini.model:") for p in problems)
        assert not any(SENTINEL in p for p in problems)

    @pytest.mark.parametrize("value", ["prod", "PRODUCTION", "", 1])
    def test_environment_must_be_a_known_value(self, value):
        assert "environment" in problems_of(environment=value)

    def test_every_problem_is_listed_at_once(self):
        with pytest.raises(SettingsError) as raised:
            settings(
                platform={"floor_fail_mode": "x", "question_budgets": {"output": 2000}},
                gemini={"base_url": "ftp://x"},
                gateway={"budgets_s": {"nope": 1.0}},
            )
        assert len(raised.value.problems) == 4

    async def test_build_engine_validates_settings_built_in_code(self):
        """Settings built directly (not from a file) are still checked at startup."""
        s = EngineSettings(platform=PlatformSettings(floor_fail_mode="sometimes"))
        with pytest.raises(SettingsError, match=r"platform\.floor_fail_mode"):
            await build_engine(s, verifier=verifier(), model=FakeDecisionModel())

    async def test_missing_floor_file_is_named(self, tmp_path):
        s = settings(catalog={"floor_files": [str(tmp_path / "missing.json")]})
        with pytest.raises(SettingsError, match=r"catalog\.floor_files\[0\].*cannot read"):
            await build_engine(s, verifier=verifier(), model=FakeDecisionModel())

    async def test_invalid_floor_file_is_named(self, tmp_path):
        bad = tmp_path / "rules.json"
        bad.write_text('{"schema_version": 1, "floor_version": 1, "rules": []}')
        s = settings(catalog={"floor_files": [str(bad)]})
        with pytest.raises(SettingsError, match=r"catalog\.floor_files\[0\].*rejected"):
            await build_engine(s, verifier=verifier(), model=FakeDecisionModel())

    @pytest.mark.parametrize("environment", ["production", "staging"])
    async def test_a_newest_floor_without_the_screening_questions_refuses_to_start(
        self, tmp_path, environment
    ):
        """Tool-description screening asks three floor questions (M2-03)."""
        doc = json.loads(FLOOR_FILE.read_text())
        doc["rules"] = [r for r in doc["rules"] if r["key"] != "p__inj_indirect"]
        trimmed = tmp_path / "rules.json"
        trimmed.write_text(json.dumps(doc))
        s = settings(environment, catalog={"floor_files": [str(trimmed)]})
        with pytest.raises(SettingsError, match=r"lacks \['p__inj_indirect'\]"):
            await build_engine(s, verifier=verifier(), model=FakeDecisionModel())
        test = settings("test", catalog={"floor_files": [str(trimmed)]})  # a test engine may
        engine = await build_engine(test, verifier=verifier(), model=FakeDecisionModel())
        await engine.shutdown()

    async def test_min_floor_version_must_exist_in_the_catalog(self):
        s = settings(platform={"min_floor_version": 2})
        with pytest.raises(SettingsError, match=r"platform\.min_floor_version: 2"):
            await build_engine(s, verifier=verifier(), model=FakeDecisionModel())

    async def test_default_floor_path_is_relative_to_the_working_directory(self, monkeypatch):
        monkeypatch.chdir(FLOOR_FILE.parents[1])
        v1_allowed = EngineSettings.from_mapping({"signed_context": {"allow_v1_hmac": True}})
        engine = await build_engine(
            v1_allowed,
            verifier=verifier(),
            model=FakeDecisionModel(),
            other_tenants=NoOtherTenantIdentifiers(),  # production: the opt-out is explicit
        )
        assert engine.catalog.floor(1) is not None
        await engine.shutdown()

    async def test_nothing_is_started_when_validation_fails(self, monkeypatch):
        """Validation runs before any resource exists: no pool is opened."""
        import guardrail_engine.engine.factory as factory

        opened = []
        monkeypatch.setattr(factory, "_connect_pool", lambda dsn: opened.append(dsn))
        monkeypatch.setenv("GUARDRAIL_PG_DSN", "postgresql://u@h/db")
        s = adapter_settings(store={"kind": "postgres"}, gemini={"paid_tier": False})
        with pytest.raises(SettingsError):
            await build_engine(s, verifier=verifier(), tenants=directory())
        assert opened == []
