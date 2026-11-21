"""TenantScope: the only tenant form the policy store accepts, issued only by the
verifiers and the authorizer."""

import ast
import copy
import pickle
from pathlib import Path

import pytest

from guardrail_engine.guard.context import HmacContextVerifier, VerifiedContext
from guardrail_engine.store.memory import InMemoryPolicyStore
from guardrail_engine.store.port import ScopeMismatchError
from guardrail_engine.tenant_scope import TenantScope, issue_scope

SRC = Path(__file__).resolve().parents[1] / "src" / "guardrail_engine"
ISSUERS = {
    "guard/context.py",  # VerifiedContext.scope: exists only after a signature verified
    "authz/authorizer.py",  # AuthzDecision.scope: only on an allowed decision
    "engine/factory.py",  # bootstrap_publish: a platform-operator tool, no request input
    "admin/tool_registry.py",  # RegistryTools: the directory's read of a tenant's accepted tools
}


def test_a_scope_cannot_be_built_from_a_string():
    with pytest.raises(TypeError):
        TenantScope("t_acmeins")
    with pytest.raises(TypeError):
        TenantScope("t_acmeins", _mint=object())


def test_a_scope_carries_a_valid_tenant_id_only():
    with pytest.raises(ValueError):
        issue_scope("not a tenant")
    assert issue_scope("t_acmeins").tenant_id == "t_acmeins"


def test_a_scope_is_immutable_and_cannot_be_pickled_into_existence():
    scope = issue_scope("t_acmeins")
    with pytest.raises(AttributeError):
        scope._tenant_id = "t_otherco"  # type: ignore[misc]
    with pytest.raises(AttributeError):
        scope.tenant_id = "t_otherco"  # type: ignore[misc]
    with pytest.raises(TypeError):
        pickle.dumps(scope)
    assert copy.copy(scope) is scope and copy.deepcopy(scope) is scope
    assert scope == issue_scope("t_acmeins") and scope != issue_scope("t_otherco")


def test_a_verified_context_cannot_be_built_from_a_string():
    """``VerifiedContext("t_other", 0).scope`` must not mint a scope."""
    with pytest.raises(TypeError):
        VerifiedContext("t_otherco", 0.0)
    with pytest.raises(TypeError):
        VerifiedContext("t_otherco", 0.0, _mint=object())


def test_a_verifiers_context_carries_the_scope_of_its_tenant():
    verifier = HmacContextVerifier(b"k" * 32)
    ctx = verifier.verify(verifier.issue("t_acmeins"))
    assert ctx.scope == issue_scope("t_acmeins") and ctx.tenant_id == "t_acmeins"


def test_only_the_two_verifiers_build_a_verified_context():
    callers = set()
    for path in SRC.rglob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "VerifiedContext"
            ):
                callers.add(path.relative_to(SRC).as_posix())
    assert callers == {"guard/context.py", "guard/signed_context.py"}


async def test_the_scoped_memory_store_refuses_another_tenant():
    store = InMemoryPolicyStore(catalog=None).scoped(issue_scope("t_acmeins"))
    with pytest.raises(ScopeMismatchError):
        await store.list_versions("t_otherco")
    assert await store.list_versions("t_acmeins") == []
    with pytest.raises(TypeError):
        InMemoryPolicyStore(catalog=None).scoped("t_acmeins")  # type: ignore[arg-type]


def test_only_the_verifiers_and_the_authorizer_import_issue_scope():
    importers = set()
    for path in SRC.rglob("*.py"):
        if path.name == "tenant_scope.py":
            continue
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and any(
                a.name == "issue_scope" for a in node.names
            ):
                importers.add(path.relative_to(SRC).as_posix())
            if isinstance(node, ast.Attribute) and node.attr == "issue_scope":
                importers.add(path.relative_to(SRC).as_posix())
    assert importers == ISSUERS
