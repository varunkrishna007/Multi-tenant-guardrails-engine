"""B3: the bundle schema enforces the tenant id rule, so a bundle for a tenant that
could never authenticate fails at publish with a clear error, not at check time."""

import pytest

from guardrail_engine.policy import ErrorCode, PolicyInvalidError, parse_bundle

BAD_IDS = ["t_acme_ins", "t_Acme", "t-acme", "t_" + "a" * 33]


@pytest.mark.parametrize("tenant_id", BAD_IDS)
def test_validate_reports_a_bad_tenant_id_at_its_path(compiler, tenant, bundle, tenant_id):
    bundle["tenant_id"] = tenant_id
    errors = compiler.validate(bundle, tenant)
    assert [(e.code, e.path) for e in errors] == [(ErrorCode.SCHEMA_INVALID, "$.tenant_id")]
    assert tenant_id not in errors[0].message  # the rule is stated, the value isn't repeated


@pytest.mark.parametrize("tenant_id", BAD_IDS)
def test_a_bundle_with_a_bad_tenant_id_cant_be_parsed(bundle, tenant_id):
    bundle["tenant_id"] = tenant_id
    with pytest.raises(PolicyInvalidError):
        parse_bundle(bundle)


def test_a_conforming_id_is_accepted(compiler, tenant, bundle):
    assert compiler.validate(bundle, tenant) == []
