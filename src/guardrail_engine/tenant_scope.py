"""The tenant a request is verified to act for, as a value the store accepts.

Row-level security sets ``app.tenant_id`` from a :class:`TenantScope`, never from a tenant id
string a caller passes. A string can come from a request body, a query field or a path; a
scope can only be made by the code that verified who the caller is:

* the signed-context verifiers (``guard/context.py``, ``VerifiedContext.scope``);
* the authorizer (``authz/authorizer.py``, ``AuthzDecision.scope``, issued only on an allowed
  decision for the path's tenant);
* the factory's ``bootstrap_publish``, a platform-operator tool that takes no request input.

``tests/test_tenant_scope.py`` fails when any other module imports :func:`issue_scope`. Python
cannot make a value truly unforgeable in-process, so this is a reviewable boundary, not a
sandbox: a handler that wants a scope has to be handed one by a verifier or the authorizer, and
a handler that builds one stands out in review and in that test.
"""

from __future__ import annotations

from typing import Any, Final, NoReturn

from guardrail_engine.tenant_ids import is_valid_tenant_id

_MINT: Final = object()


class TenantScope:
    """One verified tenant id. Immutable, hashable, and not copyable or picklable into
    existence from a string."""

    __slots__ = ("_operator", "_tenant_id")

    def __init__(self, tenant_id: str, *, operator: bool = False, _mint: object = None) -> None:
        if _mint is not _MINT:
            raise TypeError("a TenantScope is issued by a verifier or the authorizer")
        if not is_valid_tenant_id(tenant_id):
            raise ValueError("tenant id is not valid")
        object.__setattr__(self, "_tenant_id", tenant_id)
        object.__setattr__(self, "_operator", bool(operator))

    @property
    def tenant_id(self) -> str:
        return self._tenant_id  # type: ignore[no-any-return]

    @property
    def operator(self) -> bool:
        """True only for a scope the authorizer issued for an **allowed cross-tenant access by a
        platform operator**. The Postgres stores then use the operator pool (the operator
        role's policies, 007 and 014); every other scope uses the tenant-scoped application
        pool, so a normal request can never reach the operator role."""
        return self._operator  # type: ignore[no-any-return]

    def __setattr__(self, name: str, value: Any) -> NoReturn:
        raise AttributeError("a TenantScope is immutable")

    def __delattr__(self, name: str) -> NoReturn:
        raise AttributeError("a TenantScope is immutable")

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, TenantScope)
            and other.tenant_id == self.tenant_id
            and other.operator == self.operator
        )

    def __hash__(self) -> int:
        return hash(("TenantScope", self.tenant_id, self.operator))

    def __repr__(self) -> str:
        return f"TenantScope({self.tenant_id!r}{', operator' if self.operator else ''})"

    def __reduce__(self) -> NoReturn:
        raise TypeError("a TenantScope can't be pickled")

    def __copy__(self) -> TenantScope:
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> TenantScope:
        return self


def issue_scope(tenant_id: str, *, operator: bool = False) -> TenantScope:
    """Make the scope for a tenant id that a verifier or the authorizer has established.
    ``operator`` is for the authorizer alone, on an allowed cross-tenant access by a platform
    operator. Importing this is restricted (see the module docstring)."""
    return TenantScope(tenant_id, operator=operator, _mint=_MINT)
