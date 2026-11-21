"""The draft lifecycle (M2-02): read the guardrails, replace the draft, change or remove one
rule. Framework-independent: the REST adapter calls it after authenticating and authorizing.

**The tenant is the decision's scope.** Every method takes the :class:`AuthzDecision` the
authorizer returned for the request and uses only ``decision.scope``: never a tenant id from the
path, a query or a body. A decision that was not allowed, has no scope, or was made for another
endpoint than the method serves is refused (``DecisionError``, a programming error: the adapter
must not call a method with the wrong decision).

**Every write is validated by the compiler first** (AC-C0, two phases: all shape errors, then,
if the shape is right, all semantic errors) against the tenant's profile, and nothing invalid is
stored. It is then stored with its class A event (actor, diff, resulting hash; AC-A2) in one
step, by compare-and-set on the draft's ETag.

**Preconditions.** ``If-Match`` is required to change an existing draft (``PreconditionRequired``,
428), compared strongly against the current ETag (a mismatch is ``DraftConflictError``, 412;
``*`` matches any existing draft). Creating the first draft needs no ``If-Match``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from guardrail_engine.admin.drafts import (
    MAX_DRAFT_BYTES,
    DraftAuditEvent,
    DraftConflictError,
    ScopedDraftStores,
    StoredDraft,
    etag_of,
)
from guardrail_engine.authz.authorizer import AuthzDecision
from guardrail_engine.authz.model import Principal
from guardrail_engine.guard.tenants import TenantDirectory
from guardrail_engine.policy.canonical import sha256_of
from guardrail_engine.policy.catalog import Catalog, PlatformSettings
from guardrail_engine.policy.compiler import PolicyCompiler
from guardrail_engine.policy.diff import bundle_diff
from guardrail_engine.policy.document import read_bundle
from guardrail_engine.policy.errors import ErrorCode
from guardrail_engine.policy.json_document import parse_json_text
from guardrail_engine.store.port import ScopedPolicyStores
from guardrail_engine.tenant_scope import TenantScope

GET_GUARDRAILS = ("GET", "/v1/tenants/{tid}/guardrails")
PUT_DRAFT = ("PUT", "/v1/tenants/{tid}/guardrails/draft")
PATCH_RULE = ("PATCH", "/v1/tenants/{tid}/guardrails/draft/rules/{rule_id}")
DELETE_RULE = ("DELETE", "/v1/tenants/{tid}/guardrails/draft/rules/{rule_id}")


@dataclass(frozen=True, slots=True)
class DraftError:
    """One problem with a submitted draft: a stable ``code``, a JSON ``path`` and a message."""

    code: str
    path: str
    message: str


class DraftServiceError(Exception):
    """Base class for what the service raises about a request."""


class DraftInvalidError(DraftServiceError):
    """The submitted draft or rule is not valid (HTTP 422). ``errors`` lists every problem."""

    def __init__(self, errors: list[DraftError]) -> None:
        self.errors = errors
        super().__init__(f"{len(errors)} draft error(s)")


class PreconditionRequiredError(DraftServiceError):
    """``If-Match`` is needed to change an existing draft (HTTP 428)."""


class NoDraftError(DraftServiceError):
    """There is no draft to change (HTTP 404)."""


class RuleNotFoundError(DraftServiceError):
    """The draft has no tenant rule with that id (HTTP 404)."""


class RuleExistsError(DraftServiceError):
    """The draft already has a tenant rule with that id (HTTP 409)."""


class TenantUnavailableError(DraftServiceError):
    """The tenant is not in the directory or is not active (HTTP 404)."""


class DecisionError(Exception):
    """The caller passed a decision this method may not act on: a programming error."""


@dataclass(frozen=True, slots=True)
class Guardrails:
    """What ``GET guardrails`` returns: the published (active) version, the draft and the
    rollout state. The rollout is empty until publish exists (M2-07)."""

    tenant_id: str
    published: dict[str, Any] | None
    draft: StoredDraft | None
    rollout: dict[str, Any] | None = None


def _scope_of(decision: AuthzDecision, endpoint: tuple[str, str]) -> TenantScope:
    if not decision.allowed or decision.scope is None or decision.endpoint is None:
        raise DecisionError("the decision does not allow a tenant action")
    if (decision.endpoint.method, decision.endpoint.route) != endpoint:
        raise DecisionError("the decision was made for another endpoint")
    return decision.scope


def _if_match_ok(if_match: str, current_etag: str) -> bool:
    """Strong comparison (RFC 9110 §13.1.1): ``*`` matches any current draft, a weak
    validator (``W/...``) never matches."""
    candidates = [part.strip() for part in if_match.split(",")]
    return any(c == "*" or (not c.startswith("W/") and c == current_etag) for c in candidates)


def _convert(errors: Any) -> list[DraftError]:
    return [DraftError(str(e.code), e.path, e.message) for e in errors]


class DraftChangeHook(Protocol):
    """Told after every stored draft write (M5-02: the approval service cancels the approvals
    for the draft that was replaced). It must not raise."""

    async def draft_changed(
        self, scope: TenantScope, decision: AuthzDecision, principal: Principal, new_etag: str
    ) -> object: ...


class DraftService:
    def __init__(
        self,
        drafts: ScopedDraftStores,
        policies: ScopedPolicyStores,
        tenants: TenantDirectory,
        catalog: Catalog,
        settings: PlatformSettings,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        require_issuer: bool = False,
        on_change: DraftChangeHook | None = None,
    ) -> None:
        self._on_change = on_change
        self._require_issuer = require_issuer
        self._drafts = drafts
        self._policies = policies
        self._tenants = tenants
        self._catalog = catalog
        self._settings = settings
        self._clock = clock

    # ------------------------------------------------------------------ reads

    async def get_guardrails(self, decision: AuthzDecision) -> Guardrails:
        scope = _scope_of(decision, GET_GUARDRAILS)
        tenant_id = scope.tenant_id
        draft = await self._drafts.scoped(scope).get(tenant_id)
        policies = self._policies.scoped(scope)
        version = await policies.get_active_version(tenant_id)
        published = None
        if version is not None:
            info = next(
                (v for v in await policies.list_versions(tenant_id) if v.version == version), None
            )
            published = {
                "version": version,
                "bundle_hash": None if info is None else info.bundle_hash,
                "created_at": None if info is None else info.created_at.isoformat(),
            }
        return Guardrails(tenant_id, published, draft)

    # ------------------------------------------------------------------ writes

    async def put_draft(
        self, decision: AuthzDecision, principal: Principal, body: bytes, if_match: str | None
    ) -> StoredDraft:
        scope = _scope_of(decision, PUT_DRAFT)
        if len(body) > MAX_DRAFT_BYTES:
            raise DraftInvalidError(
                [DraftError("draft.too_large", "$", f"a draft is at most {MAX_DRAFT_BYTES} bytes")]
            )
        store = self._drafts.scoped(scope)
        current = await store.get(scope.tenant_id)
        expected = self._precondition(current, if_match, may_create=True)
        return await self._write(
            scope, store, decision, principal, "draft.put", current, expected, body
        )

    async def write_document(
        self,
        scope: TenantScope,
        decision: AuthzDecision,
        principal: Principal,
        action: str,
        body: bytes,
        if_match: str | None,
        detail: dict[str, Any] | None = None,
    ) -> StoredDraft:
        """Replace the existing draft with ``body`` as ``action`` (the draft's audit event
        carries it), for a caller that already holds the tenant's verified ``scope`` from its own
        endpoint's decision (M4-01 applies accepted thresholds this way). The same checks as
        a ``PUT``: the draft must exist, ``if_match`` must match its ETag, and the whole
        document is validated."""
        if len(body) > MAX_DRAFT_BYTES:
            raise DraftInvalidError(
                [DraftError("draft.too_large", "$", f"a draft is at most {MAX_DRAFT_BYTES} bytes")]
            )
        store = self._drafts.scoped(scope)
        current = await store.get(scope.tenant_id)
        expected = self._precondition(current, if_match, may_create=False)
        return await self._write(
            scope, store, decision, principal, action, current, expected, body, detail
        )

    async def patch_rule(
        self,
        decision: AuthzDecision,
        principal: Principal,
        rule_id: str,
        body: bytes,
        if_match: str | None,
    ) -> StoredDraft:
        """Create the tenant rule ``rule_id``, or change it by JSON merge patch (RFC 7396: a
        ``null`` member removes that member)."""
        scope = _scope_of(decision, PATCH_RULE)
        if len(body) > MAX_DRAFT_BYTES:
            raise DraftInvalidError(
                [DraftError("draft.too_large", "$", f"a rule is at most {MAX_DRAFT_BYTES} bytes")]
            )
        store = self._drafts.scoped(scope)
        current = await store.get(scope.tenant_id)
        expected = self._precondition(current, if_match, may_create=False)
        assert current is not None
        patch, problems = parse_json_text(body)
        if problems:
            raise DraftInvalidError(_convert(problems))
        if not isinstance(patch, dict):
            raise DraftInvalidError(
                [DraftError("draft.rule_not_object", "$", "a rule is an object")]
            )
        if "id" in patch and patch["id"] != rule_id:
            raise DraftInvalidError(
                [
                    DraftError(
                        "draft.rule_id_mismatch", "$.id", "the rule's id is the one in the path"
                    )
                ]
            )
        document = json.loads(current.document)
        rules = document.setdefault("rules", [])
        if not isinstance(rules, list):  # the stored draft was validated: not reachable
            raise DraftInvalidError([DraftError("draft.corrupt", "$.rules", "rules is not a list")])
        for i, rule in enumerate(rules):
            if isinstance(rule, dict) and rule.get("id") == rule_id:
                rules[i] = _merge_patch(rule, patch)
                break
        else:
            rules.append({**patch, "id": rule_id})
        return await self._write(
            scope,
            store,
            decision,
            principal,
            "draft.rule.put",
            current,
            expected,
            json.dumps(document).encode(),
        )

    async def add_rule(
        self,
        decision: AuthzDecision,
        principal: Principal,
        endpoint: tuple[str, str],
        rule: dict[str, Any],
        if_match: str | None,
        action: str,
    ) -> StoredDraft:
        """Add ``rule`` to the draft for the tenant of a decision made for ``endpoint`` (how a
        template is applied, M2-03). The draft must exist (``If-Match`` as for any change) and
        must not already have a rule with that id (:class:`RuleExistsError`)."""
        scope = _scope_of(decision, endpoint)
        store = self._drafts.scoped(scope)
        current = await store.get(scope.tenant_id)
        expected = self._precondition(current, if_match, may_create=False)
        assert current is not None
        document = json.loads(current.document)
        rules = document.setdefault("rules", [])
        if any(isinstance(r, dict) and r.get("id") == rule.get("id") for r in rules):
            raise RuleExistsError()
        rules.append(rule)
        return await self._write(
            scope, store, decision, principal, action, current, expected,
            json.dumps(document).encode(),
        )  # fmt: skip

    async def delete_rule(
        self, decision: AuthzDecision, principal: Principal, rule_id: str, if_match: str | None
    ) -> StoredDraft:
        scope = _scope_of(decision, DELETE_RULE)
        store = self._drafts.scoped(scope)
        current = await store.get(scope.tenant_id)
        expected = self._precondition(current, if_match, may_create=False)
        assert current is not None
        document = json.loads(current.document)
        rules = document.get("rules", [])
        kept = [r for r in rules if not (isinstance(r, dict) and r.get("id") == rule_id)]
        if len(kept) == len(rules):
            raise RuleNotFoundError()
        document["rules"] = kept
        return await self._write(
            scope,
            store,
            decision,
            principal,
            "draft.rule.delete",
            current,
            expected,
            json.dumps(document).encode(),
        )

    # ------------------------------------------------------------------ internals

    @staticmethod
    def _precondition(
        current: StoredDraft | None, if_match: str | None, *, may_create: bool
    ) -> str | None:
        """The ETag the write must find (None: no draft yet), or raises."""
        if current is None:
            if not may_create:
                raise NoDraftError()
            if if_match is not None:  # a precondition on something that doesn't exist
                raise DraftConflictError(None)
            return None
        if if_match is None:
            raise PreconditionRequiredError()
        if not _if_match_ok(if_match, current.etag):
            raise DraftConflictError(current.etag)
        return current.etag

    async def _write(
        self,
        scope: TenantScope,
        store: Any,
        decision: AuthzDecision,
        principal: Principal,
        action: str,
        current: StoredDraft | None,
        expected: str | None,
        body: bytes,
        detail: dict[str, Any] | None = None,
    ) -> StoredDraft:
        if self._require_issuer and principal.issuer is None:
            raise DecisionError("the principal has no issuer; the audit actor needs one")
        profile = await self._tenants.get(scope.tenant_id)
        if profile is None:
            raise TenantUnavailableError()
        compiler = PolicyCompiler(self._catalog, profile, self._settings)
        errors = compiler.validate(body, profile.attributes)
        edited = _edited_template_rules(errors)
        if edited:
            # Any edit to a template copy's wording or thresholds sets template_unedited to
            # false (M2-03): a rule that says it is unedited but differs is saved as edited.
            body = _mark_edited(body, edited)
            errors = compiler.validate(body, profile.attributes)
        if errors:
            raise DraftInvalidError(_convert(errors))
        parsed, shape_errors = read_bundle(body)
        assert parsed is not None and not shape_errors  # validate() passed
        document = parsed.document
        before = None if current is None else json.loads(current.document)
        resulting = sha256_of(document)
        event = DraftAuditEvent(
            at=self._clock(),
            actor=principal.actor,
            tenant_id=scope.tenant_id,
            action=action,
            before_hash=None if before is None else sha256_of(before),
            resulting_hash=resulting,
            diff=bundle_diff({} if before is None else before, document),
            cross_tenant=decision.cross_tenant,
            operator=principal.platform_operator,
            detail=detail,
        )
        assert etag_of(document) == '"' + resulting + '"'
        stored: StoredDraft = await store.replace(
            scope.tenant_id, parsed.canonical_document, expected_etag=expected, event=event
        )
        if self._on_change is not None:
            await self._on_change.draft_changed(scope, decision, principal, stored.etag)
        return stored


_TEMPLATE_MISMATCH_PATH = re.compile(r"\$\.rules\[(\d+)\]\.template_unedited")


def _edited_template_rules(errors: Any) -> set[int]:
    """The indexes of the rules with the complaint ``template_unedited: true`` on a rule that no
    longer matches its template."""
    found: set[int] = set()
    for e in errors:
        match = _TEMPLATE_MISMATCH_PATH.fullmatch(e.path)
        if e.code != ErrorCode.TEMPLATE_MISMATCH or match is None:
            continue
        found.add(int(match.group(1)))
    return found


def _mark_edited(body: bytes, indexes: set[int]) -> bytes:
    document = json.loads(body)
    for i in indexes:
        document["rules"][i]["template_unedited"] = False
    return json.dumps(document).encode()


def _merge_patch(target: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
    """RFC 7396 JSON merge patch on objects."""
    result = dict(target)
    for key, value in patch.items():
        if value is None:
            result.pop(key, None)
        elif isinstance(value, dict):
            # An object patches the member if it is an object, else patches an empty one, so
            # nulls nested in it are dropped rather than stored.
            existing = result.get(key)
            result[key] = _merge_patch(existing if isinstance(existing, dict) else {}, value)
        else:
            result[key] = value
    return result
