import pytest

from guardrail_engine.sdk.adapters.remote import CREDENTIAL_VARIABLES


@pytest.fixture(autouse=True)
def runtime_without_credentials(monkeypatch):
    """Remote mode refuses a runtime whose environment holds a provider key or a DSN; a
    developer's shell may have one, and these tests are not about that."""
    import os

    for name in list(os.environ):
        if name in CREDENTIAL_VARIABLES or name.startswith("GEMINI_KEY_"):
            monkeypatch.delenv(name)
