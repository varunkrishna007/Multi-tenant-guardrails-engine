"""The demo through the composition root (M1-11 "bench/demo adopt the factory"). Offline:
the engine is built by ``build_engine`` with ``FakeDecisionModel``; no key, no network."""

from __future__ import annotations

import json

import pytest

from demo import render, run_demo
from guardrail_engine.decision import FakeDecisionModel
from guardrail_engine.decision.port import Failed, FailureKind


def scored(text, key, q):
    """p__inj_direct scores high on the classic injection, everything else low."""
    return 0.97 if key == "p__inj_direct" and "ignore" in text.lower() else 0.02


async def demo_run(tmp_path, model, **kw):
    return await run_demo.run(model=model, out=tmp_path, log=lambda s: None, **kw)


async def test_every_verdict_comes_from_the_engine(tmp_path):
    fake = FakeDecisionModel(responder=scored)
    payload = await demo_run(tmp_path, fake)
    results = payload["results"]
    assert [r["id"] for r in results] == run_demo.DEMO_IDS
    assert payload["engine"].startswith("build_engine") and payload["pacing"].startswith("seq")
    assert payload["thresholds"] == {"block_at": 0.85, "escalate_at": 0.55, "provisional": True}
    assert len(fake.calls) == len(results)  # one model call per example, all via the engine
    for r in results:
        assert r["provider_called"] and r["reason"] == "policy" and r["rules"]
        assert all(x["p"] in (0.97, 0.02) for x in r["rules"])
    first = results[0]  # in-dir-001: "ignore all previous instructions"
    assert first["verdict"] == "block"
    assert {x["rule"]: x["action"] for x in first["rules"]}["p__inj_direct"] == "block"
    written = json.loads((tmp_path / "results.json").read_text())
    assert written == payload


async def test_the_cards_render_from_engine_results(tmp_path):
    payload = await demo_run(tmp_path, FakeDecisionModel(responder=scored))
    by_id = {r["id"]: r for r in payload["results"]}
    html = render.report(payload) + render.card_email(by_id["tr-ind-002"])
    html += render.card_obfuscation(by_id) + render.card_results(payload["results"])
    assert render.TRUTH_ENGINE.split(" · ")[0] in html  # the engine footer, not "demo-only"
    assert "demo-only scoring" not in html and "few lines in" not in html


def test_v1_results_keep_their_own_footer():
    """Results without an ``engine`` field (the v1 demo-only scoring) keep the v1 wording."""
    data = json.loads((run_demo.OUT / "results.json").read_text())
    v1 = {k: v for k, v in data.items() if k != "engine"}
    assert "demo-only scoring" in render.report(v1)
    assert "demo-only scoring" not in render.report(data)


def test_excluded_examples_are_refused_before_the_engine_is_built(tmp_path):
    golden = tmp_path / "golden.jsonl"
    rows = [
        {"id": "ok-1", "guard_point": "input", "category": "x", "content": "hi", "fires": []},
        {"id": "h-1", "guard_point": "input", "category": "x", "content": "PLACEHOLDER",
         "fires": ["d__harm_facilitation"]},
    ]  # fmt: skip
    golden.write_text("".join(json.dumps(r) + "\n" for r in rows))
    with pytest.raises(run_demo.DemoStop, match="no harmful inputs"):
        run_demo.select({r["id"]: r for r in rows}, ["ok-1", "h-1"])
    fake = FakeDecisionModel(responder=scored)

    async def go():
        await demo_run(tmp_path, fake, ids=["ok-1", "h-1"], golden_path=golden)

    import asyncio

    with pytest.raises(run_demo.DemoStop):
        asyncio.run(go())
    assert fake.calls == []  # nothing sent, not even the allowed example


@pytest.mark.parametrize(
    "script, match",
    [(lambda f: f.safety_block_next(), "provider refusal"),
     (lambda f: f.fail_next(FailureKind.AUTH), "auth failure"),
     (lambda f: f.push(Failed(kind=FailureKind.OTHER, unrecognised_code="blocklist")),
      "other failure")],
    ids=["provider_refusal", "auth", "unclassified"],
)  # fmt: skip
async def test_a_refusal_or_unclassified_failure_stops_the_demo(tmp_path, script, match):
    fake = script(FakeDecisionModel(responder=scored))
    with pytest.raises(run_demo.DemoStop, match=match):
        await demo_run(tmp_path, fake)
    assert len(fake.calls) == 1  # the first example only; nothing resent
    assert not (tmp_path / "results.json").exists()


def test_the_output_scan_refuses_a_key_or_header(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "sentinel-key-value-123")
    run_demo.scan('{"ok": true}')
    for text in ('{"x": "sentinel-key-value-123"}', '{"h": "X-Goog-Api-Key"}'):
        with pytest.raises(run_demo.DemoStop, match="output scan"):
            run_demo.scan(text)


async def test_redaction_is_recorded_and_disclosed_where_it_changed_what_the_model_saw(tmp_path):
    """M1-14 redacts on every check. The cards show the original text, so the card and the
    report say where the model saw a placeholder: counts per kind, never values."""
    payload = await demo_run(tmp_path, FakeDecisionModel(responder=scored))
    by_id = {r["id"]: r for r in payload["results"]}
    assert all(r["redaction"] == "applied" for r in payload["results"])
    assert by_id["tr-ind-002"]["pii_redacted"] == {"email": 2}
    assert by_id["pl-exf-001"]["pii_redacted"] == {"email": 1}
    assert not by_id["in-dir-001"]["pii_redacted"]
    card = render.card_email(by_id["tr-ind-002"])
    assert "2 emails" in card and "replaced with placeholders" in card
    report = render.report(payload)
    assert "tr-ind-002: 2 emails" in report and "pl-exf-001: 1 email" in report
    assert "{esc(" not in report  # the template is filled in, not printed
