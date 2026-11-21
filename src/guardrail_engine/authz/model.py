"""Roles, principals and the endpoint table (design §Admin API → Security; backlog M2-01)."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType


class Role(StrEnum):
    VIEWER = "viewer"
    GUARDRAIL_ADMIN = "guardrail_admin"
    GUARDRAIL_REVIEWER = "guardrail_reviewer"
    AUDITOR = "auditor"


ROLE_IMPLIES = MappingProxyType(
    {
        Role.VIEWER: frozenset({Role.VIEWER}),
        Role.GUARDRAIL_ADMIN: frozenset({Role.GUARDRAIL_ADMIN, Role.VIEWER}),
        Role.GUARDRAIL_REVIEWER: frozenset({Role.GUARDRAIL_REVIEWER, Role.VIEWER}),
        Role.AUDITOR: frozenset({Role.AUDITOR, Role.VIEWER}),
    }
)
"""What each role grants (decided 2026-11-17): admin, reviewer and auditor each include viewer.
No role includes another's write: an admin cannot read decision records (auditor), a reviewer
cannot edit the draft (admin), an auditor can do neither."""


def role_satisfies(held: Iterable[Role], required: Role) -> bool:
    return any(required in ROLE_IMPLIES[role] for role in held)


PLATFORM = "platform_operator"
"""The ``required`` value of a platform-only endpoint: the principal must be an operator."""


@dataclass(frozen=True, slots=True)
class Endpoint:
    """One row of the Admin API table. ``route`` uses ``{tid}`` for the tenant path part;
    ``required`` is a :class:`Role`, or :data:`PLATFORM` for platform-only routes."""

    method: str
    route: str
    required: Role | str
    approver_on_regulated: bool = False
    """Publishing also needs a second approver on regulated tiers (two-person approval, M5-02:
    recorded here, enforced by the publish service, which consumes an ``approval_id``)."""

    @property
    def tenant_scoped(self) -> bool:
        return "{tid}" in self.route


_T = "/v1/tenants/{tid}/guardrails"
ENDPOINTS: tuple[Endpoint, ...] = (
    Endpoint("GET", _T, Role.VIEWER),
    Endpoint("GET", f"{_T}/catalog", Role.VIEWER),
    Endpoint("PUT", f"{_T}/draft", Role.GUARDRAIL_ADMIN),
    Endpoint("POST", f"{_T}/draft/templates/{{template_id}}", Role.GUARDRAIL_ADMIN),
    Endpoint("PATCH", f"{_T}/draft/rules/{{rule_id}}", Role.GUARDRAIL_ADMIN),
    Endpoint("DELETE", f"{_T}/draft/rules/{{rule_id}}", Role.GUARDRAIL_ADMIN),
    Endpoint("POST", f"{_T}/draft/validate", Role.GUARDRAIL_ADMIN),
    Endpoint("POST", f"{_T}/draft/test", Role.GUARDRAIL_REVIEWER),
    Endpoint("POST", f"{_T}/draft/calibrate", Role.GUARDRAIL_REVIEWER),
    Endpoint("POST", f"{_T}/draft/thresholds", Role.GUARDRAIL_ADMIN),
    Endpoint("GET", f"{_T}/calibration/targets", Role.VIEWER),
    Endpoint("PUT", f"{_T}/calibration/targets", Role.GUARDRAIL_ADMIN),
    Endpoint("GET", f"{_T}/draft/approvals", Role.VIEWER),
    Endpoint("POST", f"{_T}/draft/approvals", Role.GUARDRAIL_ADMIN),
    Endpoint("POST", f"{_T}/draft/approvals/{{id}}/approve", Role.GUARDRAIL_ADMIN),
    Endpoint("POST", f"{_T}/draft/publish", Role.GUARDRAIL_ADMIN, approver_on_regulated=True),
    Endpoint("GET", f"{_T}/versions", Role.VIEWER),
    Endpoint("POST", f"{_T}/versions/{{v}}/rollback", Role.GUARDRAIL_ADMIN),
    Endpoint("GET", f"{_T}/candidate/comparison", Role.VIEWER),
    Endpoint("PATCH", f"{_T}/candidate", Role.GUARDRAIL_ADMIN),
    Endpoint("POST", f"{_T}/candidate/promote", Role.GUARDRAIL_ADMIN, approver_on_regulated=True),
    Endpoint("POST", f"{_T}/candidate/abandon", Role.GUARDRAIL_ADMIN),
    Endpoint("POST", f"{_T}/golden-sets", Role.GUARDRAIL_REVIEWER),
    Endpoint("GET", f"{_T}/golden-sets", Role.VIEWER),
    Endpoint("GET", f"{_T}/golden-sets/{{set_id}}", Role.VIEWER),
    Endpoint("GET", f"{_T}/tools", Role.VIEWER),
    Endpoint("PUT", f"{_T}/tools/{{name}}", Role.GUARDRAIL_ADMIN),
    Endpoint("DELETE", f"{_T}/tools/{{name}}", Role.GUARDRAIL_ADMIN),
    Endpoint("POST", f"{_T}/tools/{{name}}/review", Role.GUARDRAIL_REVIEWER),
    Endpoint("GET", f"{_T}/decisions", Role.AUDITOR),
    Endpoint("GET", f"{_T}/decisions/{{request_id}}/content", Role.AUDITOR),
    Endpoint("GET", f"{_T}/metrics", Role.VIEWER),
    Endpoint("GET", f"{_T}/escalations", Role.VIEWER),
    Endpoint("GET", f"{_T}/escalations/{{id}}", Role.VIEWER),
    Endpoint("POST", f"{_T}/escalations/{{id}}/resolve", Role.GUARDRAIL_REVIEWER),
    Endpoint("GET", f"{_T}/floor", PLATFORM),
    Endpoint("PUT", f"{_T}/tier", PLATFORM),  # M5-01: only platform ops set the tier
    Endpoint("POST", f"{_T}/floor/repin", PLATFORM),
    Endpoint("POST", f"{_T}/floor/promote", PLATFORM),
    Endpoint("GET", "/v1/platform/floors", PLATFORM),
    Endpoint("POST", "/v1/platform/floors/{version}/release", PLATFORM),
    Endpoint("POST", "/v1/platform/floors/{version}/approve", PLATFORM),
    Endpoint("POST", "/v1/platform/floors/{version}/halt", PLATFORM),
    Endpoint("DELETE", "/v1/platform/floors/{version}/halt", PLATFORM),
    Endpoint("POST", "/v1/platform/floors/{version}/repin", PLATFORM),
    Endpoint("GET", "/v1/platform/floors/{version}/rollout", PLATFORM),
    Endpoint("PUT", "/v1/platform/minimum-floor", PLATFORM),
    Endpoint("GET", "/v1/platform/redteam/nightly", PLATFORM),
    Endpoint("GET", "/v1/platform/redteam/nightly/{tenant_id}", PLATFORM),
    Endpoint("GET", "/v1/platform/redteam/quarantine", PLATFORM),
    Endpoint("POST", "/v1/platform/redteam/quarantine/clear", PLATFORM),
    Endpoint("GET", "/v1/platform/packs", PLATFORM),
    Endpoint("PUT", "/v1/platform/packs/{pack}", PLATFORM),
)
"""Every route of design §Admin API, with the role it needs. A new route is added here first;
a test checks that each row is covered for every role."""


@dataclass(frozen=True, slots=True)
class Principal:
    """An authenticated caller. ``tenant_id`` is the token's ``tenant_id`` claim (None for a
    platform operator with no home tenant); ``roles`` are the roles the token carries;
    ``platform_operator`` is the token's operator claim. Built only by the authentication layer
    from a verified token, never from a request body."""

    subject: str
    tenant_id: str | None
    roles: frozenset[Role] = field(default_factory=frozenset)
    platform_operator: bool = False
    issuer: str | None = None
    """The verified ``iss`` of the token. A subject is unique only within its issuer, and the
    platform issuer and the tenant issuers (M2-01) are different namespaces."""
    service_account: bool = False
    """The token says it belongs to a machine identity, not a person (M5-02): the OIDC adapter
    sets it from the token's ``service_account`` claim being ``true`` (the name is
    configurable), or from ``gty`` being ``client-credentials``. A service account can't approve
    a publish (R2). A token that carries neither marker is treated as a person, so the identity
    provider has to emit one for its machine clients."""

    def __post_init__(self) -> None:
        if not self.subject:
            raise ValueError("a principal needs a subject")
        object.__setattr__(self, "roles", frozenset(Role(r) for r in self.roles))

    @property
    def actor(self) -> str:
        """The identity recorded in audit events: ``<issuer>#<subject>``, so the same subject
        from two issuers is two actors. Just the subject when there is no issuer (a principal
        made by something other than the OIDC adapter, such as a test)."""
        return self.subject if self.issuer is None else f"{self.issuer}#{self.subject}"
