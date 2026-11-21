"""M5-03: the Guard Service hands a check's content to the class C writer only when the version
that decided it says ``store_content: full``, and what it hands over is the **post-redaction**
text the model saw. AC-G2's style: the raw PII values are searched for in what is stored."""

import hashlib
import logging
from datetime import timedelta

from guard_fixtures import ALPHA, BETA, Env, bundle, profile, rule

from guardrail_engine.content import (
    EffectiveContentTerm,
    InMemoryStoredContent,
    StoredContentWriter,
)
from guardrail_engine.guard import Decision, Plan, Reason, ToolCall, ToolResult, Turn
from guardrail_engine.policy import PlatformSettings, PolicyCompiler, TenantAttributes, parse_bundle
from guardrail_engine.tenant_scope import issue_scope

EMAIL = "jo.smith@example.com"
CARD = "4111 1111 1111 1111"
PHONE = "+1 201-555-0123"
SSN = "078-05-1120"
NINO = "QQ 12 34 56 C"
IBAN = "GB82 WEST 1234 5698 7654 32"
RAW = [EMAIL, "jo.smith@", CARD, PHONE, SSN, NINO, IBAN]
CONTENT = f"Contact {EMAIL} or {PHONE}; card {CARD}, ssn {SSN}, nino {NINO}, iban {IBAN}."


def full(tenant=ALPHA, days=7, **extra):
    doc = bundle(tenant, rules=[rule("adv")])
    doc["audit"] = {"store_content": "full", "content_days": days}
    return doc | extra


class Rig:
    def __init__(self, env: Env):
        self.env = env
        self.store = InMemoryStoredContent()
        self.writer = StoredContentWriter(
            self.store,
            EffectiveContentTerm(
                catalog=env.catalog, settings=env.settings, directory=env.directory
            ),
            flush_interval_s=0.01,
        )
        env.service.attach_content(self.writer)

    async def rows(self):
        await self.writer.flush()
        return self.store.all()


async def rig(*tenants):
    env = Env(tenants=list(tenants) or [profile(ALPHA), profile(BETA)])
    return env, Rig(env)


async def test_content_storage_is_off_by_default():
    env, r = await rig()
    async with env:
        await env.publish(bundle(ALPHA, rules=[rule("adv")]))  # no audit section at all
        await env.check(ALPHA, content="a perfectly ordinary message")
        b = bundle(BETA, rules=[rule("adv")])
        b["audit"] = {"store_content": "hash_only"}
        await env.publish(b)
        await env.check(BETA, content="another one")
        assert await r.rows() == []
        assert r.writer.queued == 0 and r.writer.dropped == 0 and not r.writer.skipped


async def test_only_the_post_redaction_text_is_stored_and_no_raw_pii_ever_lands():
    env, r = await rig()
    async with env:
        await env.publish(full())
        conversation = (
            Turn("user", f"my card is {CARD}"),
            Plan(f'{{"steps": [{{"tool": "claims.status", "args": {{"ssn": "{SSN}"}}}}]}}'),
            ToolCall("claims.status", f'{{"nino": "{NINO}"}}'),
            ToolResult("claims.status", f"pay to {IBAN}"),
        )
        verdict = await env.check(ALPHA, content=CONTENT, conversation=conversation)
        assert verdict.decision is Decision.ALLOW
        (row,) = await r.rows()
        [call] = env.fake.calls
    for value in RAW:
        assert value not in row.content, value
    for placeholder in ("[EMAIL]@example.com", "[CARD]", "[PHONE]", "[SSN]", "[NINO]", "[IBAN]"):
        assert placeholder in row.content
    assert row.content in call.input  # exactly the text the model saw, and nothing else of it
    assert not any(v in row.content for v in ("my card is", "claims.status"))  # no conversation
    assert row.content_sha256 == "sha256:" + hashlib.sha256(CONTENT.encode()).hexdigest()
    assert (row.tenant_id, row.guard_point, row.request_id) == (
        ALPHA, "output", verdict.request_id,
    )  # fmt: skip
    assert row.retain_until == verdict.checked_at + timedelta(days=7)
    assert row.bundle_version == verdict.bundle_version and row.truncated is False


async def test_the_audit_record_and_the_verdict_still_hold_no_content():
    env, r = await rig()
    async with env:
        await env.publish(full())
        verdict = await env.check(ALPHA, content=f"zebra-quartz {EMAIL}")
        await r.rows()
        dumped = verdict.model_dump_json() + "".join(a.model_dump_json() for a in env.audit.records)
    assert "zebra-quartz" not in dumped and EMAIL not in dumped and "[EMAIL]" not in dumped


async def test_a_check_that_never_reached_redaction_stores_nothing():
    """A deterministic block runs on the raw content before redaction: there is no post-redaction
    text to keep, and the raw text is never stored in its place."""
    env, r = await rig()
    async with env:
        doc = full()
        doc["deterministic"] = {
            "deny_patterns": [{"id": "x", "regex": "forbidden", "action": "block"}]
        }
        await env.publish(doc)
        verdict = await env.check(ALPHA, content=f"this is forbidden, mail {EMAIL}")
        assert verdict.decision is Decision.BLOCK and verdict.reason is Reason.DETERMINISTIC
        assert await r.rows() == []


async def test_each_tenant_is_stored_under_its_own_verified_id_and_only_if_it_asked():
    env, r = await rig()
    async with env:
        await env.publish(full(ALPHA))
        await env.publish(bundle(BETA, rules=[rule("adv")]))
        await env.check(ALPHA, content="alpha text")
        await env.check(BETA, content="beta text")
        rows = await r.rows()
        assert [(x.tenant_id, x.content) for x in rows] == [(ALPHA, "alpha text")]
        assert [
            x.content for x in await r.store.get(issue_scope(BETA), rows[0].request_id, None)
        ] == []


async def test_a_writer_that_raises_never_changes_the_verdict(caplog):
    env = Env()

    class Broken:
        def submit(self, request):
            raise RuntimeError("the queue exploded")

    async with env:
        await env.publish(full())
        env.service.attach_content(Broken())
        with caplog.at_level(logging.ERROR):
            verdict = await env.check(ALPHA, content="hello there")
        assert verdict.decision is Decision.ALLOW
    assert "could not be handed over" in caplog.text


async def test_a_full_queue_never_delays_or_changes_the_check_and_is_counted():
    env = Env()
    store = InMemoryStoredContent()
    w = StoredContentWriter(
        store,
        EffectiveContentTerm(
            catalog=env.catalog, settings=env.settings, directory=env.directory
        ),
        capacity=1,
        flush_interval_s=0.01,
    )  # fmt: skip
    env.service.attach_content(w)
    async with env:
        await env.publish(full())
        verdicts = [await env.check(ALPHA, content=f"message {i}") for i in range(4)]
    assert all(v.decision is Decision.ALLOW for v in verdicts)
    assert w.queued == 1 and w.dropped == 3


# ------------------------------------------------------------------ a healthcare tenant


def healthcare_env(baa):
    from policy_fixtures import (
        FLOOR_DOCUMENTS,  # noqa: F401
        HEALTHCARE_V1,  # the pack: content cap 30, BAA required
    )

    from guardrail_engine.policy import InMemoryCatalog

    base = Env().catalog
    catalog = InMemoryCatalog(
        floors=[base.floor(1)], packs=[HEALTHCARE_V1], tier_required_packs={}
    )  # fmt: skip
    attrs = TenantAttributes(tenant_id=ALPHA, baa=baa)
    from guardrail_engine.guard.tenants import TenantProfile

    prof = TenantProfile.build(attrs, "insurance", slug="alpha")
    env = Env(catalog=catalog, tenants=[prof])
    return env, Rig(env), attrs


async def publish_as(env, document, attrs):
    parsed = parse_bundle(document)
    compiled = PolicyCompiler(env.catalog, profile(ALPHA), env.settings).compile(parsed, attrs)
    await env.inner_store.put_version(ALPHA, parsed, bundle_hash=compiled.bundle_hash)
    await env.inner_store.set_active_version(ALPHA, parsed.bundle.version)


async def test_a_healthcare_tenant_with_a_baa_stores_30_days_at_most_and_stops_when_the_flag_goes():
    env, r, attrs = healthcare_env(baa=True)
    async with env:
        doc = bundle(ALPHA, packs=["domain/healthcare@1"])
        doc["audit"] = {"store_content": "full", "content_days": 30}
        await publish_as(env, doc, attrs)
        verdict = await env.check(ALPHA, content="my chart note")
        (row,) = await r.rows()
        assert row.retain_until == verdict.checked_at + timedelta(days=30)
        # the BAA flag is taken away after the publish: nothing more is stored
        from guardrail_engine.guard.tenants import TenantProfile

        env.directory.put(
            TenantProfile.build(
                TenantAttributes(tenant_id=ALPHA, baa=False), "insurance", slug="alpha"
            )
        )
        r.writer._terms.clear()
        await env.check(ALPHA, content="a second chart note")
        assert len(await r.rows()) == 1
        assert r.writer.skipped == {"baa_missing": 1} and r.writer.dropped == 0


def test_the_compiler_refuses_a_healthcare_bundle_without_the_baa_flag():
    env, _, _ = healthcare_env(baa=False)
    doc = bundle(ALPHA, packs=["domain/healthcare@1"])
    doc["audit"] = {"store_content": "full"}
    errors = PolicyCompiler(env.catalog, profile(ALPHA), env.settings).validate(
        parse_bundle(doc), TenantAttributes(tenant_id=ALPHA, baa=False)
    )
    assert [e.code.value for e in errors] == ["audit.content_requires_baa"]


def test_the_platform_settings_keep_the_r3_ninety_day_cap():
    assert PlatformSettings().standard_retention.content_max_days == 90
