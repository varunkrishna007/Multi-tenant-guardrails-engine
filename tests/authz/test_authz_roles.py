"""M2-01 AC-T1 and the role table: a test per endpoint and role, the tenant match, operators and
the cross-tenant audit. Offline."""

import itertools

import pytest

from guardrail_engine.authz import (
    ENDPOINTS,
    ROLE_IMPLIES,
    Authorizer,
    InMemoryAuthzAudit,
    Principal,
    Role,
    role_satisfies,
)
from guardrail_engine.authz.model import PLATFORM

ALPHA, BETA = "t_alpha1", "t_beta2"
ALL_ROLES = list(Role)
TENANT_ENDPOINTS = [e for e in ENDPOINTS if e.tenant_scoped and e.required != PLATFORM]
PLATFORM_TENANT_ENDPOINTS = [e for e in ENDPOINTS if e.tenant_scoped and e.required == PLATFORM]


def route_args(endpoint, tid=ALPHA):
    return endpoint.method, endpoint.route, (tid if endpoint.tenant_scoped else None)


def make(audit=None):
    audit = audit if audit is not None else InMemoryAuthzAudit()
    return Authorizer(audit, clock=lambda: 1_700_000_000.0), audit


def user(*roles, tenant=ALPHA, operator=False, subject="alice"):
    return Principal(subject, tenant, frozenset(roles), operator)


# ---------------------------------------------------------------------------- the table


def test_the_endpoint_table_is_the_design_table_row_for_row():
    assert [(e.method, e.route.removeprefix("/v1/tenants/{tid}/guardrails") or "/", e.required)
            for e in ENDPOINTS] == [
        ("GET", "/", Role.VIEWER),
        ("GET", "/catalog", Role.VIEWER),
        ("PUT", "/draft", Role.GUARDRAIL_ADMIN),
        ("POST", "/draft/templates/{template_id}", Role.GUARDRAIL_ADMIN),
        ("PATCH", "/draft/rules/{rule_id}", Role.GUARDRAIL_ADMIN),
        ("DELETE", "/draft/rules/{rule_id}", Role.GUARDRAIL_ADMIN),
        ("POST", "/draft/validate", Role.GUARDRAIL_ADMIN),
        ("POST", "/draft/test", Role.GUARDRAIL_REVIEWER),
        ("POST", "/draft/calibrate", Role.GUARDRAIL_REVIEWER),
        ("POST", "/draft/thresholds", Role.GUARDRAIL_ADMIN),
        ("GET", "/calibration/targets", Role.VIEWER),
        ("PUT", "/calibration/targets", Role.GUARDRAIL_ADMIN),
        ("GET", "/draft/approvals", Role.VIEWER),  # M5-02
        ("POST", "/draft/approvals", Role.GUARDRAIL_ADMIN),  # M5-02
        ("POST", "/draft/approvals/{id}/approve", Role.GUARDRAIL_ADMIN),  # M5-02
        ("POST", "/draft/publish", Role.GUARDRAIL_ADMIN),
        ("GET", "/versions", Role.VIEWER),
        ("POST", "/versions/{v}/rollback", Role.GUARDRAIL_ADMIN),
        ("GET", "/candidate/comparison", Role.VIEWER),
        ("PATCH", "/candidate", Role.GUARDRAIL_ADMIN),
        ("POST", "/candidate/promote", Role.GUARDRAIL_ADMIN),
        ("POST", "/candidate/abandon", Role.GUARDRAIL_ADMIN),
        ("POST", "/golden-sets", Role.GUARDRAIL_REVIEWER),
        ("GET", "/golden-sets", Role.VIEWER),
        ("GET", "/golden-sets/{set_id}", Role.VIEWER),
        ("GET", "/tools", Role.VIEWER),
        ("PUT", "/tools/{name}", Role.GUARDRAIL_ADMIN),
        ("DELETE", "/tools/{name}", Role.GUARDRAIL_ADMIN),
        ("POST", "/tools/{name}/review", Role.GUARDRAIL_REVIEWER),
        ("GET", "/decisions", Role.AUDITOR),
        ("GET", "/decisions/{request_id}/content", Role.AUDITOR),
        ("GET", "/metrics", Role.VIEWER),
        ("GET", "/escalations", Role.VIEWER),
        ("GET", "/escalations/{id}", Role.VIEWER),
        ("POST", "/escalations/{id}/resolve", Role.GUARDRAIL_REVIEWER),
        ("GET", "/floor", PLATFORM),
        ("PUT", "/tier", PLATFORM),  # M5-01
        ("POST", "/floor/repin", PLATFORM),
        ("POST", "/floor/promote", PLATFORM),
        ("GET", "/v1/platform/floors", PLATFORM),
        ("POST", "/v1/platform/floors/{version}/release", PLATFORM),
        ("POST", "/v1/platform/floors/{version}/approve", PLATFORM),
        ("POST", "/v1/platform/floors/{version}/halt", PLATFORM),
        ("DELETE", "/v1/platform/floors/{version}/halt", PLATFORM),
        ("POST", "/v1/platform/floors/{version}/repin", PLATFORM),
        ("GET", "/v1/platform/floors/{version}/rollout", PLATFORM),
        ("PUT", "/v1/platform/minimum-floor", PLATFORM),
        ("GET", "/v1/platform/redteam/nightly", PLATFORM),
        ("GET", "/v1/platform/redteam/nightly/{tenant_id}", PLATFORM),
        ("GET", "/v1/platform/redteam/quarantine", PLATFORM),
        ("POST", "/v1/platform/redteam/quarantine/clear", PLATFORM),
        ("GET", "/v1/platform/provider/degraded", PLATFORM),
        ("PUT", "/v1/platform/provider/degraded", PLATFORM),
        ("GET", "/v1/platform/packs", PLATFORM),
        ("PUT", "/v1/platform/packs/{pack}", PLATFORM),
    ]  # fmt: skip
    assert len({(e.method, e.route) for e in ENDPOINTS}) == len(ENDPOINTS)
    assert [e.route for e in ENDPOINTS if e.approver_on_regulated] == [
        "/v1/tenants/{tid}/guardrails/draft/publish",
        "/v1/tenants/{tid}/guardrails/candidate/promote",  # promoting enforces too (R2)
    ]


def test_roles_imply_viewer_and_nothing_else():
    assert ROLE_IMPLIES[Role.VIEWER] == {Role.VIEWER}
    for role in (Role.GUARDRAIL_ADMIN, Role.GUARDRAIL_REVIEWER, Role.AUDITOR):
        assert ROLE_IMPLIES[role] == {role, Role.VIEWER}
    assert not role_satisfies([], Role.VIEWER)
    assert not role_satisfies([Role.GUARDRAIL_ADMIN], Role.AUDITOR)
    assert not role_satisfies([Role.AUDITOR], Role.GUARDRAIL_REVIEWER)


# ---------------------------------------------------------------------------- AC-T1 per endpoint


@pytest.mark.parametrize("endpoint", TENANT_ENDPOINTS, ids=lambda e: f"{e.method} {e.route}")
@pytest.mark.parametrize("role", ALL_ROLES)
async def test_every_endpoint_for_every_role_on_the_own_tenant(endpoint, role):
    authorizer, audit = make()
    decision = await authorizer.authorize(user(role), *route_args(endpoint))
    expected = role_satisfies([role], endpoint.required)
    assert decision.allowed is expected
    assert decision.status == (200 if expected else 403)
    assert decision.reason == ("ok" if expected else "missing_role")
    assert audit.events == []  # same tenant: nothing to audit


@pytest.mark.parametrize("endpoint", TENANT_ENDPOINTS, ids=lambda e: f"{e.method} {e.route}")
async def test_a_principal_with_no_roles_is_refused_everywhere(endpoint):
    authorizer, _ = make()
    decision = await authorizer.authorize(user(), *route_args(endpoint))
    assert (decision.allowed, decision.status, decision.reason) == (False, 403, "missing_role")


@pytest.mark.parametrize("endpoint", TENANT_ENDPOINTS, ids=lambda e: f"{e.method} {e.route}")
async def test_a_path_tenant_that_does_not_match_the_token_is_403_even_with_every_role(endpoint):
    authorizer, audit = make()
    everything = user(*ALL_ROLES)
    decision = await authorizer.authorize(everything, *route_args(endpoint, tid=BETA))
    assert (decision.allowed, decision.status, decision.reason) == (False, 403, "tenant_mismatch")
    assert decision.cross_tenant is True
    [event] = audit.events  # the attempt is recorded
    assert (event.allowed, event.target_tenant_id, event.actor) == (False, BETA, "alice")


async def test_the_publish_decision_says_a_regulated_tier_needs_a_second_approver():
    authorizer, _ = make()
    publish = next(e for e in ENDPOINTS if e.route.endswith("/draft/publish"))
    decision = await authorizer.authorize(user(Role.GUARDRAIL_ADMIN), *route_args(publish))
    assert decision.allowed and decision.needs_second_approver
    other = next(e for e in ENDPOINTS if e.route.endswith("/draft/validate"))
    assert not (await authorizer.authorize(user(Role.GUARDRAIL_ADMIN), *route_args(other))
                ).needs_second_approver  # fmt: skip


@pytest.mark.parametrize("tid", ["", "t_Acme", "t-acme", "t_acme_ins", "t_" + "a" * 33, None, 7])
async def test_a_malformed_path_tenant_is_refused_before_anything_else_and_not_audited(tid):
    authorizer, audit = make()
    endpoint = TENANT_ENDPOINTS[0]
    decision = await authorizer.authorize(
        user(Role.VIEWER, operator=True), endpoint.method, endpoint.route, tid
    )
    assert (decision.allowed, decision.status, decision.reason) == (False, 403, "invalid_tenant_id")
    assert audit.events == []


async def test_an_unknown_route_is_a_programming_error_not_a_decision():
    authorizer, _ = make()
    with pytest.raises(ValueError, match="no such route"):
        await authorizer.authorize(user(Role.VIEWER), "GET", "/v1/tenants/{tid}/other", ALPHA)


# ---------------------------------------------------------------------------- platform operators


@pytest.mark.parametrize("endpoint", [e for e in ENDPOINTS if not e.tenant_scoped],
                         ids=lambda e: e.route)  # fmt: skip
async def test_platform_routes_need_the_operator_flag_whatever_the_roles(endpoint):
    authorizer, _ = make()
    refused = await authorizer.authorize(user(*ALL_ROLES), *route_args(endpoint))
    assert (refused.allowed, refused.status, refused.reason) == (
        False,
        403,
        "not_platform_operator",
    )
    allowed = await authorizer.authorize(user(operator=True, tenant=None), *route_args(endpoint))
    assert allowed.allowed and allowed.reason == "ok"


@pytest.mark.parametrize("endpoint", TENANT_ENDPOINTS, ids=lambda e: f"{e.method} {e.route}")
@pytest.mark.parametrize("role", ALL_ROLES)
async def test_an_operator_crosses_tenants_but_still_needs_the_role_and_is_audited_first(
    endpoint, role
):
    authorizer, audit = make()
    operator = user(role, tenant=None, operator=True, subject="ops-1")
    decision = await authorizer.authorize(operator, *route_args(endpoint, tid=BETA))
    expected = role_satisfies([role], endpoint.required)
    assert decision.allowed is expected and decision.cross_tenant is True
    [event] = audit.events
    assert (event.actor, event.actor_tenant_id, event.target_tenant_id) == ("ops-1", None, BETA)
    assert (event.method, event.route, event.allowed) == (endpoint.method, endpoint.route, expected)
    assert event.reason == ("ok" if expected else "missing_role")


async def test_an_operator_on_their_own_home_tenant_is_not_a_cross_tenant_access():
    authorizer, audit = make()
    decision = await authorizer.authorize(
        user(Role.VIEWER, tenant=ALPHA, operator=True), "GET", TENANT_ENDPOINTS[0].route, ALPHA
    )
    assert decision.allowed and decision.cross_tenant is False and audit.events == []


async def test_if_the_audit_cannot_be_written_the_cross_tenant_access_is_refused():
    audit = InMemoryAuthzAudit()
    audit.fail = True
    authorizer, _ = make(audit)
    operator = user(Role.VIEWER, tenant=None, operator=True)
    decision = await authorizer.authorize(operator, "GET", TENANT_ENDPOINTS[0].route, BETA)
    assert (decision.allowed, decision.status, decision.reason) == (False, 403, "audit_unavailable")


async def test_a_failing_audit_never_changes_a_denial_and_never_blocks_own_tenant_access():
    audit = InMemoryAuthzAudit()
    audit.fail = True
    authorizer, _ = make(audit)
    denied = await authorizer.authorize(user(Role.VIEWER), "GET", TENANT_ENDPOINTS[0].route, BETA)
    assert (denied.allowed, denied.reason) == (False, "tenant_mismatch")
    own = await authorizer.authorize(user(Role.VIEWER), "GET", TENANT_ENDPOINTS[0].route, ALPHA)
    assert own.allowed


async def test_the_audit_is_written_before_the_decision_is_returned():
    order: list[str] = []

    class Sink:
        async def record(self, event):
            order.append("audit")

    authorizer, _ = make(Sink())
    decision = await authorizer.authorize(
        user(Role.VIEWER, tenant=None, operator=True), "GET", TENANT_ENDPOINTS[0].route, BETA
    )
    order.append("returned")
    assert decision.allowed and order == ["audit", "returned"]


def test_the_audit_event_holds_identifiers_and_a_fixed_reason_only():
    import dataclasses

    from guardrail_engine.authz import CrossTenantEvent

    fields = {f.name for f in dataclasses.fields(CrossTenantEvent)}
    assert fields == {"at", "actor", "actor_tenant_id", "target_tenant_id", "method", "route",
                      "allowed", "reason"}  # fmt: skip


def test_a_principal_needs_a_subject_and_known_roles():
    with pytest.raises(ValueError):
        Principal("", ALPHA)
    with pytest.raises(ValueError):
        Principal("a", ALPHA, frozenset({"root"}))
    assert Principal("a", ALPHA, frozenset({"viewer"})).roles == {Role.VIEWER}


def test_every_tenant_endpoint_is_exercised_for_every_role():
    """The parametrised tests above cover this product; keep it from going stale."""
    assert (
        len(list(itertools.product(TENANT_ENDPOINTS, ALL_ROLES))) == 35 * 4
    )  # the role-based tenant routes; the platform ones are below


# ---------------------------------------------------------------------------- the scope


async def test_an_allowed_tenant_decision_carries_the_scope_of_the_paths_tenant():
    authorizer, _ = make()
    endpoint = next(e for e in TENANT_ENDPOINTS if e.required == Role.VIEWER)
    own = await authorizer.authorize(user(Role.VIEWER), *route_args(endpoint))
    assert own.allowed and own.scope is not None and own.scope.tenant_id == ALPHA
    # an operator reaching another tenant gets that tenant's scope, after the audit write
    other = await authorizer.authorize(
        user(Role.VIEWER, tenant=None, operator=True), *route_args(endpoint, BETA)
    )
    assert other.allowed and other.scope is not None and other.scope.tenant_id == BETA


async def test_a_denied_decision_and_a_platform_route_carry_no_scope():
    authorizer, _ = make()
    endpoint = next(e for e in TENANT_ENDPOINTS if e.required == Role.GUARDRAIL_ADMIN)
    denied = await authorizer.authorize(user(Role.VIEWER), *route_args(endpoint))
    assert not denied.allowed and denied.scope is None
    crossing = await authorizer.authorize(user(Role.GUARDRAIL_ADMIN), *route_args(endpoint, BETA))
    assert not crossing.allowed and crossing.scope is None
    platform = next(e for e in ENDPOINTS if not e.tenant_scoped)
    ok = await authorizer.authorize(
        user(Role.VIEWER, tenant=None, operator=True), *route_args(platform)
    )
    assert ok.allowed and ok.scope is None


# ---------------------------------------------------------------------------- M2-09 platform rows


def test_the_platform_floor_rows_are_the_operators_alone():
    assert len(PLATFORM_TENANT_ENDPOINTS) == 4  # floor, tier (M5-01), re-pin, promote
    platform_only = [e for e in ENDPOINTS if not e.tenant_scoped and e.required == PLATFORM]
    # packs (2), the nightly red-team (4), the provider hold (2, M7-11) and the floor (8)
    assert len(platform_only) == 16


@pytest.mark.parametrize(
    "endpoint", PLATFORM_TENANT_ENDPOINTS, ids=lambda e: f"{e.method} {e.route}"
)
@pytest.mark.parametrize("role", ALL_ROLES)
async def test_no_tenant_role_reaches_a_platform_step_on_its_own_tenant(endpoint, role):
    """R5.1: a tenant can't approve, block or start anything of the floor's."""
    authorizer, _ = make()
    decision = await authorizer.authorize(user(*ALL_ROLES), *route_args(endpoint))
    assert (decision.allowed, decision.reason) == (False, "not_platform_operator")


@pytest.mark.parametrize(
    "endpoint", PLATFORM_TENANT_ENDPOINTS, ids=lambda e: f"{e.method} {e.route}"
)
async def test_an_operator_reaches_a_platform_step_on_any_tenant_with_an_audited_scope(endpoint):
    authorizer, audit = make()
    operator = user(tenant=None, operator=True, subject="ops-1")  # no tenant role at all
    decision = await authorizer.authorize(operator, *route_args(endpoint, tid=BETA))
    assert decision.allowed and decision.cross_tenant
    assert decision.scope is not None and decision.scope.operator
    [event] = audit.events
    assert (event.allowed, event.target_tenant_id, event.actor) == (True, BETA, "ops-1")


@pytest.mark.parametrize("endpoint", [e for e in ENDPOINTS if not e.tenant_scoped])
async def test_a_tenant_principal_is_refused_every_platform_route(endpoint):
    authorizer, _ = make()
    decision = await authorizer.authorize(user(*ALL_ROLES), endpoint.method, endpoint.route)
    assert (decision.allowed, decision.reason) == (False, "not_platform_operator")
    operator = user(operator=True)
    assert (await authorizer.authorize(operator, endpoint.method, endpoint.route)).allowed
