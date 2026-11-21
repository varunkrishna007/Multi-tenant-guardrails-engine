"""Store and driver exception text reaches the service log only with
credentials masked, so a DSN with a password in a driver's error can't reach shipped logs.
Every place the policy cache logs such text is covered: an outage with nothing to serve, an
outage served from last-known-good, and a background refresh that fails."""

from __future__ import annotations

import logging

import pytest
from guard_fixtures import ALPHA, Env, bundle

from guardrail_engine.guard import Decision, Reason
from guardrail_engine.guard.policy_cache import log_note, mask_secrets
from guardrail_engine.guard.verdict import PolicySource

PASSWORD = "PwSentinelQ7zK"
DSN_ERRORS = [
    f"could not connect to postgresql://app:{PASSWORD}@db.example.internal:5432/policies",
    f"invalid DSN: postgres://app:{PASSWORD}/x@db.example.internal/policies",  # '/' in it
    f"invalid DSN: postgresql://app:pa@{PASSWORD}@db.example.internal/policies",  # '@' in it
    f"connection failed (host=db.example.internal user=app password={PASSWORD} dbname=p)",
    f"connection failed: password='{PASSWORD} with spaces' host=db",
    f'connection failed: PASSWORD = "{PASSWORD}"',
    f"retrying postgresql://{PASSWORD}@db.example.internal/policies after timeout",
    # A raw space in the userinfo (asyncpg accepts it), libpq's environment
    # variable, and a bare ``pass=`` key.
    f"invalid DSN: postgresql://app:{PASSWORD} w@db.example.internal/policies",
    f"invalid DSN: postgresql://app:p w{PASSWORD}@db.example.internal/policies",
    f"environment: PGPASSWORD={PASSWORD} PGHOST=db",
    f"connection failed (pass={PASSWORD})",
]


@pytest.mark.parametrize("text", DSN_ERRORS)
def test_mask_secrets_removes_the_password(text):
    masked = mask_secrets(text)
    assert PASSWORD not in masked
    assert "***" in masked


def test_mask_secrets_keeps_ordinary_text():
    text = "relation policy_bundle_versions does not exist; see https://example.com/docs"
    assert mask_secrets(text) == text
    assert mask_secrets("postgresql://db.example.internal/policies") == (
        "postgresql://db.example.internal/policies"
    )


def test_userinfo_masking_stops_at_the_next_url():
    """The userinfo runs to the last ``@`` on the line, but not into a later URL."""
    text = f"postgresql://app:p w{PASSWORD}@db/x failed; see https://example.com/docs"
    assert mask_secrets(text) == "postgresql://***@db/x failed; see https://example.com/docs"


def test_masking_happens_before_truncation():
    """A long prefix pushes the DSN to the 200-character cut: what survives the cut must
    already be masked, not the start of an unmasked password."""
    text = "x" * 170 + f" postgresql://app:{PASSWORD}@db/policies"
    note = log_note(ConnectionError(text))
    assert len(note) <= 200 + len(" ()")
    assert PASSWORD[:4] not in note


def logged(caplog: pytest.LogCaptureFixture) -> str:
    formatter = logging.Formatter("%(name)s %(levelname)s %(message)s")
    return "\n".join(formatter.format(r) for r in caplog.records)


@pytest.mark.parametrize("text", DSN_ERRORS)
async def test_outage_with_nothing_to_serve_logs_no_password(caplog, text):
    caplog.set_level(logging.DEBUG)
    async with Env() as env:
        await env.publish(bundle(ALPHA))
        env.store.fail = ConnectionError(text)
        verdict = await env.check(ALPHA)
    assert (verdict.decision, verdict.reason) == (Decision.BLOCK, Reason.POLICY_UNAVAILABLE)
    out = logged(caplog)
    assert "policy refresh failed for tenant" in out  # the error was logged...
    assert PASSWORD not in out and PASSWORD not in repr(verdict)  # ...without the password


@pytest.mark.parametrize("text", DSN_ERRORS)
async def test_outage_served_from_last_known_good_logs_no_password(caplog, text):
    caplog.set_level(logging.DEBUG)
    async with Env() as env:
        await env.publish(bundle(ALPHA))
        await env.check(ALPHA)
        env.store.fail = ConnectionError(text)
        env.service.policy_cache.invalidate(ALPHA)
        verdict = await env.check(ALPHA)
    assert verdict.policy_source is PolicySource.LAST_KNOWN_GOOD
    out = logged(caplog)
    assert "serving last-known-good" in out
    assert PASSWORD not in out


async def test_a_failed_background_refresh_logs_no_password_or_traceback(caplog, monkeypatch):
    """The background task's own failure (not a store error, which the refresh handles) is
    logged by type and masked text, without a traceback that would repeat the text."""
    caplog.set_level(logging.DEBUG)
    async with Env() as env:
        await env.publish(bundle(ALPHA))
        await env.check(ALPHA)
        cache = env.service.policy_cache

        async def broken(tenant_id, state):
            raise RuntimeError(DSN_ERRORS[0])

        monkeypatch.setattr(cache, "_revalidate", broken)
        cache._state[ALPHA].fresh_until = float("-inf")  # stale: revalidate in background
        await env.check(ALPHA)
        await cache.drain()
    out = logged(caplog)
    assert "background policy refresh for" in out and "RuntimeError" in out
    assert PASSWORD not in out
    assert all(r.exc_info is None for r in caplog.records if "background" in r.getMessage())
