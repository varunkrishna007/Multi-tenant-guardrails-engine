"""Authorization for the Admin API (M2-01, AC-T1): who may call which endpoint on which tenant.

Framework-independent: the REST layer (M2-02) authenticates the caller (OIDC, M2-01 step 5) into
a :class:`Principal` and asks :meth:`Authorizer.authorize` before every handler runs.
"""

from guardrail_engine.authz.authentication import (
    REASONS,
    AuthenticationError,
    Authenticator,
)
from guardrail_engine.authz.authorizer import (
    Authorizer,
    AuthzAuditSink,
    AuthzDecision,
    CrossTenantEvent,
    InMemoryAuthzAudit,
)
from guardrail_engine.authz.model import (
    ENDPOINTS,
    ROLE_IMPLIES,
    Endpoint,
    Principal,
    Role,
    role_satisfies,
)

__all__ = [
    "ENDPOINTS",
    "REASONS",
    "ROLE_IMPLIES",
    "AuthenticationError",
    "Authenticator",
    "Authorizer",
    "AuthzAuditSink",
    "AuthzDecision",
    "CrossTenantEvent",
    "Endpoint",
    "InMemoryAuthzAudit",
    "Principal",
    "Role",
    "role_satisfies",
]
