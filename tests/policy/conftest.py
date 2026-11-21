"""pytest fixtures for the policy compiler tests. The data lives in policy_fixtures.py."""

import copy

import pytest
from policy_fixtures import TOOLS, make_catalog, valid_bundle

from guardrail_engine.policy import (
    InMemoryToolRegistry,
    PlatformSettings,
    PolicyCompiler,
    TenantAttributes,
)


@pytest.fixture
def settings() -> PlatformSettings:
    return PlatformSettings(min_floor_version=2)


@pytest.fixture
def compiler(settings) -> PolicyCompiler:
    return PolicyCompiler(make_catalog(), InMemoryToolRegistry(TOOLS), settings)


@pytest.fixture
def tenant() -> TenantAttributes:
    return TenantAttributes(tenant_id="t_acmeins")


@pytest.fixture
def bundle() -> dict:
    return copy.deepcopy(valid_bundle())
