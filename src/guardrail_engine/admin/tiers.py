"""``PUT /v1/tenants/{tid}/guardrails/tier`` (M5-01): a platform operator sets a tenant's tier.

**Only a platform operator.** The route is a platform route in the authz table
(:data:`~guardrail_engine.authz.model.PLATFORM`): the authorizer answers 403
``not_platform_operator`` to any other caller, a tenant's ``guardrail_admin`` included, and
audits the cross-tenant access of an operator who passes. The provisioner checks the operator
flag again (second line). The tenant has no other route, and no field of a bundle, a draft or
any other body reaches the directory: the tier is not in anything a tenant writes.

The body is ``{"tier": "regulated", "reason": "...", "expected_version": 3}``; ``expected_version``
(the directory record's version the operator read) is optional, and when given a changed record
is a 409. The answer says what happened and when it takes effect: the approval gate and the
retention floors at once, the required packs and rules at the tenant's next publish (the active
version keeps running; a candidate that lacks them can't be promoted), the dedicated project
(M5-06) at once for new checks, and the requirements the running version and the candidate lack
(``unmet_requirements``, ``unmet_candidate_requirements``), for which an alert was raised.
"""

from __future__ import annotations

from typing import Any

from guardrail_engine.admin.service import DraftServiceError, _scope_of
from guardrail_engine.authz.authorizer import AuthzDecision
from guardrail_engine.authz.model import Principal
from guardrail_engine.directory.model import TenantDirectoryStore, TenantNotFound
from guardrail_engine.directory.provisioning import TenantProvisioner
from guardrail_engine.directory.tier import CatalogTierImpact
from guardrail_engine.policy.catalog import Catalog
from guardrail_engine.policy.document import ParsedBundle, parse_bundle
from guardrail_engine.policy.json_document import parse_json_text
from guardrail_engine.tenant_scope import TenantScope

TIER_ENDPOINT = ("PUT", "/v1/tenants/{tid}/guardrails/tier")


class TierRequestError(DraftServiceError):
    """The body is not acceptable (HTTP 422); the message names the field."""


class TierService:
    def __init__(
        self,
        provisioner: TenantProvisioner,
        directory: TenantDirectoryStore,
        catalog: Catalog,
        lifecycle: Any,
    ) -> None:
        """``lifecycle``: the scoped lifecycle stores, to read the tenant's active version
        under the operator's scope (the same access the floor re-pin has)."""
        self._provisioner = provisioner
        self._directory = directory
        self._catalog = catalog
        self._lifecycle = lifecycle

    async def set_tier(
        self, decision: AuthzDecision, principal: Principal, body: bytes
    ) -> dict[str, Any]:
        scope = _scope_of(decision, TIER_ENDPOINT)
        tier, reason, expected = _read_body(body)
        record = await self._directory.get(scope.tenant_id)
        if record is None:
            raise TenantNotFound
        change = await self._provisioner.set_tier(
            principal,
            scope.tenant_id,
            expected if expected is not None else record.version,
            tier,
            reason,
            impact=CatalogTierImpact(
                self._catalog, self._loader(scope), self._loader(scope, candidate=True)
            ),
        )
        after = change.record
        return {
            "tenant_id": after.tenant_id,
            "tier": after.tier,
            "previous_tier": change.previous_tier,
            "version": after.version,
            "project": after.project,
            "approval_required": after.tier != "standard" or "two_person_publish" in after.flags,
            "unmet_requirements": list(change.gaps),
            "unmet_candidate_requirements": list(change.candidate_gaps),
            "takes_effect": {
                "approval_and_retention": "at once",
                "required_packs_and_rules": (
                    "at the next publish or promotion; the active version keeps running"
                ),
            },
        }

    def _loader(self, scope: TenantScope, *, candidate: bool = False):  # type: ignore[no-untyped-def]
        async def load(tenant_id: str) -> ParsedBundle | None:
            store = self._lifecycle.scoped(scope)
            state = await store.state(tenant_id)
            if candidate:
                version = None if state.candidate is None else state.candidate.version
            else:
                version = state.active
            if version is None:
                return None
            document = await store.document(tenant_id, version)
            return None if document is None else parse_bundle(document)

        return load


def _read_body(body: bytes) -> tuple[str, str, int | None]:
    doc, problems = parse_json_text(body.decode("utf-8", "replace"))
    if problems or not isinstance(doc, dict):
        raise TierRequestError("the body must be a JSON object")
    unknown = sorted(set(doc) - {"tier", "reason", "expected_version"})
    if unknown:
        raise TierRequestError("unknown field: only tier, reason and expected_version")
    tier, reason, expected = doc.get("tier"), doc.get("reason"), doc.get("expected_version")
    if not isinstance(tier, str) or not isinstance(reason, str):
        raise TierRequestError("tier and reason are required text")
    if expected is not None and (isinstance(expected, bool) or not isinstance(expected, int)):
        raise TierRequestError("expected_version must be a whole number")
    return tier, reason, expected
