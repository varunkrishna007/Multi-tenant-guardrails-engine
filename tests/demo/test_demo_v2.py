"""Demo v2, cards 4-9. Offline: the engine is built by ``build_engine`` with a fake model;
no key, no network, no live call."""

from __future__ import annotations

import html as htmllib
import json
import re
from types import SimpleNamespace

import pytest

from demo import render_v2, run_demo, run_demo_v2
from guardrail_engine.decision import FakeDecisionModel
from guardrail_engine.guard.verdict import Action

v2 = run_demo_v2


def responder(text, key, q):
    """Scores each pack, floor and tenant rule high on the examples that should fire."""
    t = text.lower()
    high = {
        "d__self_harm_risk": "point in going on" in t,
        "d__vulnerability": any(
            s in t for s in ("passed away", "point in going on", "lost my job", "died last week")
        ),
        "d__bias_protected_basis": any(s in t for s in ("female", "surname")),
        "d__bias_stereotype": "older customers" in t,
        "p__inj_direct": any(s in t for s in ("ignore", "forget", "ignora", "zignoruj")),
        "t__fin_adv_01": "growth fund" in t,
    }
    if key == "d__vulnerability" and high[key]:
        return 0.99  # at the API's clamp: above the pack rule's block level
    return 0.96 if high.get(key) else 0.03


class Spy(FakeDecisionModel):
    """Records every input and question set the engine sends."""

    def __init__(self, **kw):
        super().__init__(**kw)
        self.sent = []

    async def decide(self, text, questions):
        self.sent.append((text, dict(questions)))
        return await super().decide(text, questions)


@pytest.fixture(scope="module")
def goldens():
    return {s: v2.load_golden(s) for s in v2.SOURCES}


async def full_run(tmp_path=None, model=None, write=False):
    model = model or FakeDecisionModel(responder=responder)
    out = tmp_path or run_demo.OUT
    return await v2.run_all(model=model, out=out, log=lambda s: None, write=write)


# ------------------------------------------------------------------ the shims


def test_the_pack_is_loaded_without_the_harm_rule():
    pack = v2.load_pack()
    assert pack.ref == "domain/responsible_ai@1"
    assert sorted(pack.caps) == [
        "d__bias_protected_basis", "d__bias_stereotype", "d__harassment",
        "d__manipulation", "d__self_harm_risk", "d__vulnerability",
    ]  # fmt: skip
    assert pack.not_loaded == ("d__harm_facilitation",)
    assert pack.caps["d__self_harm_risk"] == pack.caps["d__vulnerability"] == "escalate"
    assert pack.caps["d__harassment"] == "block"
    assert {r.key for r in pack.version.rules} == set(pack.caps)


async def test_an_escalate_only_rule_at_the_block_level_still_escalates():
    """Acceptance: the engine's own max_action cap holds a pack rule at escalate even when the
    model's probability reaches its block level (here 0.99, the API's clamp). The demo reports
    what the thresholds alone would have called for."""
    payload = await full_run()
    row = next(r for r in payload["card4"] if r["id"] == "in-vu-002")
    by_rule = {r["rule"]: r for r in row["rules"]}
    assert by_rule["d__vulnerability"]["p"] == 0.99
    assert by_rule["d__vulnerability"]["engine_action"] == "block"  # uncapped: what p calls for
    assert by_rule["d__vulnerability"]["action"] == "escalate"  # capped, by the engine
    assert row["engine_decision"] == "escalate" and row["verdict"] == "escalate"
    assert row["capped_by_max_action"] is True


async def test_a_floor_block_is_not_capped():
    """The cap belongs to the pack rule, not the check: a floor rule that blocks still does."""
    fake = FakeDecisionModel(
        responder=lambda t, k, q: 0.99 if k in ("d__vulnerability", "p__inj_direct") else 0.02
    )
    async with v2.demo_engine(fake) as demo:
        ex = {**v2.select(v2.CARD4[:1], {"rai": v2.load_golden("rai")})[0]}
        row = await v2.score(demo, v2.MAIN, ex)
    assert row["engine_decision"] == "block" and row["verdict"] == "block"
    assert {r["rule"]: r["action"] for r in row["rules"]}["p__inj_direct"] == "block"


def test_the_cap_report_never_changes_the_engines_decision():
    """The engine applies the cap; the demo only reports it, and keeps the engine's decision."""
    rules = [
        SimpleNamespace(
            key="d__x", p=0.99, action=Action.ESCALATE, layer="pack", mode="enforce",
            block_at=0.9, escalate_at=0.5,
        )
    ]  # fmt: skip
    rows, decision, capped = v2.apply_max_action(rules, {}, "escalate", "policy")
    assert decision == "escalate" and capped is True
    assert (rows[0]["action"], rows[0]["engine_action"]) == ("escalate", "block")
    _, decision, capped = v2.apply_max_action(rules, {}, "escalate", "model_failure")
    assert (decision, capped) == ("escalate", False)  # not an answered check: nothing to report


def test_a_shadow_rule_never_acts():
    shadow = SimpleNamespace(
        key="d__s", p=0.9, action=Action.BLOCK, layer="pack", mode="shadow",
        block_at=0.85, escalate_at=0.55,
    )  # fmt: skip
    enforced = SimpleNamespace(
        key="p__ok", p=0.1, action=Action.ALLOW, layer="floor", mode="enforce",
        block_at=0.85, escalate_at=0.55,
    )  # fmt: skip
    rules = [shadow, enforced]
    _, decision, _ = v2.apply_max_action(rules, {}, "allow", "policy")
    assert decision == "allow"


# ------------------------------------------------------------------ no harmful inputs


def test_every_pick_exists_and_the_live_ones_are_all_sendable(goldens):
    """Ids repeat across the two sets, so each pick names its set. Card 4's picks are sendable
    (the live run may use them). Cards 6 and 7 show bias examples that M4-10's conservative scope
    withholds from every provider: they exist, run only on the engine's own fake model, and a run
    that goes to a provider refuses them."""
    rows = v2.select(v2.CARD4, goldens)
    assert [r["id"] for r in rows] == [p.id for p in v2.CARD4]
    for picks in (v2.CARD6_BLOCKED, v2.CARD6_ALLOWED):
        rows = v2.select(picks, goldens, provider=False)  # offline: nothing is sent anywhere
        assert [r["id"] for r in rows] == [p.id for p in picks]
    withheld = [
        p
        for p in v2.CARD6_BLOCKED
        if run_demo.live_exclusion(next(r for r in goldens[p.source] if r["id"] == p.id))
        is not None
    ]
    assert withheld  # card 6's blocked examples are the discriminatory ones
    with pytest.raises(v2.DemoStop, match="no harmful inputs"):
        v2.select(v2.CARD6_BLOCKED, goldens)  # a provider run refuses them
    for pick in v2.CARD7_PAIRS:
        members = v2.pair_members(pick, goldens[pick.source], provider=False)
        assert len(members) == 2
    assert {p.source for p in v2.CARD7_PAIRS} == {"rai", "fl"}


def test_excluded_and_unknown_examples_are_refused_before_the_engine_is_built():
    rows = [{"id": "h-1", "guard_point": "input", "category": "x", "content": "PLACEHOLDER",
             "fires": ["d__harm_facilitation"]},
            {"id": "n-1", "guard_point": "input", "category": "x", "content": "PLACEHOLDER",
             "fires": [], "no_live_run": True}]  # fmt: skip
    goldens = {"rai": rows}
    for pick in (v2.Pick("rai", "h-1"), v2.Pick("rai", "n-1")):
        with pytest.raises(v2.DemoStop, match="no harmful inputs"):
            v2.select([pick], goldens)
    with pytest.raises(v2.DemoStop, match="unknown golden ids"):
        v2.select([v2.Pick("rai", "nope")], goldens)
    pair = [{**rows[0], "pair": "p-1"}, {**rows[0], "id": "h-2", "pair": "p-1"}]
    with pytest.raises(v2.DemoStop, match="no harmful inputs"):
        v2.pair_members(v2.Pick("rai", "p-1"), pair)


async def test_the_harm_rule_and_no_harm_example_ever_reaches_the_model():
    """The observe-only harm rule isn't loaded, so its question text is never sent, and every
    input the model saw is a benign pick."""
    spy = Spy(responder=responder)
    payload = await full_run(model=spy)
    assert spy.sent and all("d__harm_facilitation" not in qs for _, qs in spy.sent)
    assert payload["pack_rules_not_loaded"] == ["d__harm_facilitation"]
    assert not any("facilitation" in key for _, qs in spy.sent for key in qs)


async def test_a_provider_refusal_stops_the_demo_at_the_first_check():
    fake = FakeDecisionModel(responder=responder).safety_block_next()
    with pytest.raises(run_demo.DemoStop, match="provider refusal"):
        await full_run(model=fake)
    assert len(fake.calls) == 1  # nothing after it, nothing resent


# ------------------------------------------------------------------ the run


async def test_the_whole_run_goes_through_the_engine(tmp_path):
    spy = Spy(responder=responder)
    payload = await full_run(tmp_path, model=spy, write=True)
    assert len(payload["card4"]) == 3 and len(payload["card7"]) == 8
    assert len(payload["card6"]["blocked"]) == len(payload["card6"]["allowed"]) == 3
    assert len(payload["card8"]["samples"]) == 2
    assert len(spy.sent) == 3 + 6 + 16 + 2  # one model call per check; card 9 has its own fake
    assert payload["not_answered"] == [] and payload["pacing"].startswith("sequential")
    assert payload["model"] == "fake (tests)" and payload["engine"].startswith("build_engine")
    assert [r["verdict"] for r in payload["card4"]] == ["escalate", "escalate", "allow"]
    assert [r["expected"] for r in payload["card4"]] == ["escalate", "escalate", "allow"]
    assert [r["verdict"] for r in payload["card6"]["blocked"]] == ["block"] * 3
    assert [r["verdict"] for r in payload["card6"]["allowed"]] == ["allow"] * 3
    assert all(r["provider_called"] for r in v2_rows(payload))
    written = (tmp_path / "results-v2.json").read_text()
    assert json.loads(written) == payload
    assert "x-goog-api-key" not in written.lower() and "authorization" not in written.lower()


def v2_rows(p):
    rows = p["card4"] + p["card6"]["blocked"] + p["card6"]["allowed"] + p["card8"]["samples"]
    return rows + [r for x in p["card7"] for r in (x["a"], x["b"])]


def test_a_pair_is_flagged_when_the_verdicts_differ_or_the_gap_is_over_a_tenth():
    def row(verdict, p):
        return {"verdict": verdict, "outcome": "answered",
                "rules": [{"rule": "r", "p": p, "action": verdict}]}  # fmt: skip

    pick = v2.Pick("fl", "fl-cf-x")
    same = v2.pair_result(pick, row("allow", 0.04), row("allow", 0.09))
    assert (same["same_verdict"], same["flagged"], same["delta_p"]) == (True, False, 0.05)
    gap = v2.pair_result(pick, row("allow", 0.04), row("allow", 0.20))
    assert gap["same_verdict"] and gap["flagged"] and gap["delta_p"] == 0.16
    differs = v2.pair_result(pick, row("allow", 0.50), row("block", 0.90))
    assert not differs["same_verdict"] and differs["flagged"]
    unanswered = v2.pair_result(pick, row("allow", 0.1), {**row("allow", 0.9), "outcome": "x"})
    assert not unanswered["answered"] and not unanswered["flagged"]


async def test_card_8_counts_are_the_real_compilers_for_the_tenant_file():
    payload = await full_run()
    counts = payload["card8"]["compiled"]["guard_points"]
    floor = json.loads(v2.FLOOR.read_text())["rules"]
    pack = v2.load_pack()
    bundle = v2.custom_bundle()
    for gp, c in counts.items():
        assert c["floor"] == sum(gp in r["guard_points"] for r in floor)
        assert c["pack"] == sum(gp in r.guard_points for r in pack.version.rules)
        assert c["tenant"] == sum(gp in r["guard_points"] for r in bundle["rules"])
        assert c["total"] == c["floor"] + c["pack"] + c["tenant"]
    assert counts["output"]["tenant"] == 2 and counts["output"]["budget"] == 50
    assert counts["input"]["budget"] == 200
    # The counts are of the policy the engine ran: the checks carry the same bundle hash.
    assert {r["bundle_hash"] for r in payload["card8"]["samples"]} == {
        payload["card8"]["compiled"]["bundle_hash"]
    }
    fired, near = payload["card8"]["samples"]
    assert (fired["verdict"], near["verdict"]) == ("block", "allow")
    assert {r["rule"] for r in fired["rules"]} >= {"t__fin_adv_01", "t__claims_promise_01"}


async def test_card_9_is_a_simulated_timeout_that_blocks_with_a_retryable_message():
    c = (await full_run())["card9"]
    assert c["simulated"] is True
    assert (c["decision"], c["reason"], c["failure_reason"]) == (
        "block",
        "model_failure",
        "timeout",
    )
    assert c["retryable"] is True and c["released"] is False
    assert c["model_calls"] == 2  # the call and the gateway's one retry, both scripted to time out
    assert "temporarily unavailable" in c["user_message"].lower()
    assert c["user_message"] != c["policy_message"] and "policy" in c["policy_message"]
    assert (c["blocks"], c["policy_blocks"], c["model_failures"]) == (1, 0, 1)


def test_the_cli_refuses_to_make_live_calls_without_the_flag(capsys):
    assert v2.main([]) == 2
    assert "--live" in capsys.readouterr().err


# ------------------------------------------------------------------ the cards


@pytest.fixture
async def payload():
    return await full_run()


async def test_every_page_renders_and_a_fake_model_is_stamped_simulated(payload):
    pages = render_v2.pages(payload)
    assert sorted(pages) == [
        "card-4-support.html", "card-5-harm.html", "card-6-bias.html", "card-7-fairness.html",
        "card-8-tenant.html", "card-9-failure.html", "report-v2.html",
    ]  # fmt: skip
    for name, text in pages.items():
        assert "<title>" in text and "class='foot'" in text, name
        if name not in ("card-5-harm.html", "card-9-failure.html"):
            assert "SIMULATED PREVIEW" in text, name  # a fake model never passes for Gemini
    assert "Text only" in pages["card-5-harm.html"]
    assert "Simulated failure" in pages["card-9-failure.html"]


async def test_no_card_shows_a_latency_figure(payload):
    for name, text in render_v2.pages(payload).items():
        visible = re.sub(r"<style>.*?</style>", "", text, flags=re.S)
        # The report may say that no figures are shown; nothing else mentions latency.
        visible = visible.replace("No latency figures are shown anywhere.", "")
        assert "latency" not in visible.lower(), name
        assert not re.search(r"\b\d+(\.\d+)?\s?ms\b", visible), name


async def test_card_texts_say_what_the_spec_requires(payload):
    pages = render_v2.pages(payload)
    assert render_v2.SUPPORT_LINE in pages["card-4-support.html"]
    assert "never block" in pages["card-4-support.html"]
    assert render_v2.CLAIMS_BOUNDARY in pages["card-6-bias.html"]
    assert render_v2.CLAIMS_BOUNDARY in pages["report-v2.html"]
    harm = pages["card-5-harm.html"]
    assert "observe-only" in harm and "provider_safety" in harm and "Nothing was sent" in harm
    for row in v2_rows(payload):  # card 5 quotes no example
        assert row["content"] not in harm
    assert "Simulated failure" in pages["card-9-failure.html"]


async def test_card_7_never_claims_unbiased_and_its_title_follows_the_result(payload):
    card = render_v2.card_7(payload)
    assert payload["card7"] and not any(x["flagged"] for x in payload["card7"])
    assert "Same message, different name: same verdict." in card
    assert card.count("unbiased") == 1 and "not that the guard is unbiased" in card
    flagged = json.loads(json.dumps(payload))
    flagged["card7"][-1]["flagged"] = True
    flagged["card7"][-1]["same_verdict"] = False
    changed = render_v2.card_7(flagged)
    assert "did the verdict change?" in changed and 'class="flag"' in changed
    assert "Same message, different name: same verdict." not in changed


async def test_an_unanswered_check_is_never_shown_as_a_verdict(payload):
    broken = json.loads(json.dumps(payload))
    row = broken["card6"]["blocked"][0]
    row.update(outcome="model_failure", reason="model_failure", provider_called=True)
    html = render_v2.card_6(broken)
    assert "no answer (model_failure)" in html
    admission = broken["card6"]["allowed"][0]
    admission.update(provider_called=False, reason="model_failure", outcome="model_failure")
    assert render_v2.card_6(broken).count("no answer (model_failure)") == 2


async def test_card_6_title_says_only_what_the_results_support(payload):
    """The spec's title needs all six checks answered and each where its label puts it."""
    spec = "Bias in decisions, caught; accommodations, allowed."
    assert spec in render_v2.card_6(payload)
    silent = json.loads(json.dumps(payload))
    silent["card6"]["allowed"][0].update(outcome="model_failure", reason="model_failure")
    html = htmllib.unescape(render_v2.card_6(silent))
    assert spec not in html and "1 of 6 checks got no answer from the model" in html
    wrong = json.loads(json.dumps(payload))
    wrong["card6"]["allowed"][0]["verdict"] = "block"
    html = htmllib.unescape(render_v2.card_6(wrong))
    assert spec not in html and "1 of 6 verdicts differ from the example's label" in html


async def test_card_7_does_not_compare_a_pair_the_model_did_not_answer(payload):
    silent = json.loads(json.dumps(payload))
    pair = silent["card7"][0]
    pair["a"].update(outcome="model_failure", reason="model_failure")
    pair["answered"], pair["flagged"] = False, False
    html = htmllib.unescape(render_v2.card_7(silent))
    assert "same verdict on the 7 pairs that got an answer" in html
    assert "7 of 7 answered pairs got the same verdict" in html
    assert "1 pair got no answer from the model" in html and "aren't compared" in html
    assert "Same message, different name: same verdict." not in html
    assert "7 of 7 answered pairs" in render_v2.report(silent)


# ------------------------------------------------------------------ the one-time re-run

from guardrail_engine.decision.port import Failed, FailureKind  # noqa: E402

FLAKY = ("accounts.set_language", "quotes.adjust", "Emily. Can I add my partner",
         "Aisha. Can I add my partner")  # fmt: skip
"""Text from the four checks that got no answer in the live run (tc-ok-004, tc-ok-002, in-cf-001,
in-cf-002)."""


class Flaky(FakeDecisionModel):
    """Times out on inputs carrying a marker while ``failing`` is true (the provider's bad
    window); answers everything else."""

    def __init__(self, markers=FLAKY, failing=True, **kw):
        super().__init__(**kw)
        self.markers, self.failing, self.sent = markers, failing, []

    async def decide(self, text, questions):
        self.sent.append(text)
        if self.failing and any(m in text for m in self.markers):
            return Failed(kind=FailureKind.TIMEOUT)
        return await super().decide(text, questions)


def quiet(_):
    return None


async def first_run(tmp_path):
    """Both results files, as the live run wrote them: four checks got no answer."""
    await run_demo.run(model=FakeDecisionModel(responder=responder), out=tmp_path, log=quiet)
    payload = await v2.run_all(
        model=Flaky(responder=responder), out=tmp_path, log=quiet, write=True
    )
    assert sorted(payload["not_answered"]) == ["in-cf-001", "in-cf-002", "tc-ok-002", "tc-ok-004"]
    return tmp_path / "results-v2.json", tmp_path / "results.json"


async def test_the_rerun_resends_only_the_unanswered_checks_once(tmp_path):
    path, v1 = await first_run(tmp_path)
    good = Flaky(responder=responder, failing=False)
    payload = await v2.rerun_unanswered(path, v1, model=good, log=quiet)
    assert len(good.sent) == 4  # the four, and nothing that had been answered
    assert payload["not_answered"] == []
    assert payload["rerun"] == {
        "at": payload["rerun"]["at"], "ids": ["tc-ok-004", "tc-ok-002", "in-cf-001", "in-cf-002"],
        "first_run_checks": 45, "first_run_unanswered": 4, "answered": 4, "unanswered": 0,
        "provider_calls": 4,
    }  # fmt: skip
    redone = {r["id"]: r for r in v2.all_live(payload) if r.get("rerun")}
    assert sorted(redone) == ["in-cf-001", "in-cf-002", "tc-ok-002", "tc-ok-004"]
    for row in redone.values():
        assert row["outcome"] == "answered" and row["provider_called"] and row["rules"]
        assert row["first_attempt"]["reason"] == "model_failure"
        assert row["first_attempt"]["provider_calls"] == 2  # call plus the gateway's retry
    pair = next(x for x in payload["card7"] if x["pair"] == "rai-cf-001")
    assert pair["answered"] and pair["a"]["rerun"] and pair["delta_p"] is not None
    assert json.loads(path.read_text()) == payload


async def test_a_second_rerun_is_refused(tmp_path):
    path, v1 = await first_run(tmp_path)
    await v2.rerun_unanswered(path, v1, model=Flaky(responder=responder, failing=False), log=quiet)
    spy = Flaky(responder=responder, failing=False)
    with pytest.raises(v2.DemoStop, match="already re-run once"):
        await v2.rerun_unanswered(path, v1, model=spy, log=quiet)
    assert spy.sent == []


async def test_a_check_that_fails_again_stays_no_answer_and_is_not_retried_further(tmp_path):
    path, v1 = await first_run(tmp_path)
    bad = Flaky(responder=responder, failing=True)
    payload = await v2.rerun_unanswered(path, v1, model=bad, log=quiet)
    assert len(bad.sent) == 8  # four checks, each the call and the gateway's one retry: no more
    assert sorted(payload["not_answered"]) == ["in-cf-001", "in-cf-002", "tc-ok-002", "tc-ok-004"]
    assert payload["rerun"]["answered"] == 0 and payload["rerun"]["unanswered"] == 4
    assert payload["rerun"]["provider_calls"] == 8
    for row in v2.unanswered_rows(payload):
        assert row["failure_kind"] == "timeout"  # recorded this time
        assert row["outcome"] == "model_failure" and row["rerun"] is True
    html = htmllib.unescape(render_v2.card_6(payload))
    assert "4 of 45 checks got no answer from the model" in html
    assert "still got no answer" in html and "no answer (model_failure)" in html
    pair = payload["card7"][0]
    assert not pair["answered"] and not pair["flagged"]


async def test_a_refusal_during_the_rerun_stops_it_and_writes_nothing(tmp_path):
    path, v1 = await first_run(tmp_path)
    before = path.read_text()
    refusing = Flaky(responder=responder, failing=False).safety_block_next()
    with pytest.raises(run_demo.DemoStop, match="provider refusal"):
        await v2.rerun_unanswered(path, v1, model=refusing, log=quiet)
    assert len(refusing.calls) == 1 and path.read_text() == before


async def test_an_excluded_example_is_refused_before_anything_is_sent(tmp_path, monkeypatch):
    path, v1 = await first_run(tmp_path)
    real = v2.live_exclusion
    monkeypatch.setattr(
        v2, "live_exclusion", lambda r: "marked" if r["id"] == "tc-ok-002" else real(r)
    )
    spy = Flaky(responder=responder, failing=False)
    with pytest.raises(v2.DemoStop, match="no harmful inputs"):
        await v2.rerun_unanswered(path, v1, model=spy, log=quiet)
    assert spy.sent == []


async def test_nothing_to_rerun_when_every_check_was_answered(tmp_path):
    def fake():
        return FakeDecisionModel(responder=responder)

    await run_demo.run(model=fake(), out=tmp_path, log=quiet)
    await v2.run_all(model=fake(), out=tmp_path, log=quiet, write=True)
    with pytest.raises(v2.DemoStop, match="nothing to re-run"):
        await v2.rerun_unanswered(
            tmp_path / "results-v2.json", tmp_path / "results.json", model=fake(), log=quiet
        )


async def test_the_cards_say_what_happened_in_the_first_run(tmp_path):
    path, v1 = await first_run(tmp_path)
    payload = await v2.rerun_unanswered(
        path, v1, model=Flaky(responder=responder, failing=False), log=quiet
    )
    note = "In the first run, 4 of 45 checks got no answer from the model"
    for html in (render_v2.card_6(payload), render_v2.card_7(payload), render_v2.report(payload)):
        text = htmllib.unescape(html)
        assert note in text and "They were re-run once: 4 answered." in text
        assert "answered on a re-run" in text
    assert "answered on a re-run" not in render_v2.card_4(payload)  # no re-run row on card 4
    assert note not in render_v2.card_4(payload)


# ------------------------------------------------------------------ a provider run


class ProviderStandIn:
    """Not a ``FakeDecisionModel``, so the demo treats the run as one that goes to a provider
    (every example is then checked for withholding); it answers like the fake, sending nothing."""

    def __init__(self):
        self._inner = Spy(responder=responder)
        self.model_id = self._inner.model_id

    async def decide(self, text, questions):
        return await self._inner.decide(text, questions)

    def __getattr__(self, name):
        return getattr(self._inner, name)


async def test_a_provider_run_skips_the_withheld_blocked_column_and_never_sends_it(tmp_path):
    stand_in = ProviderStandIn()
    payload = await v2.run_all(model=stand_in, out=tmp_path, log=lambda s: None, write=False)
    assert payload["card6"]["blocked"] == [] and payload["card6"]["blocked_offline_only"] is True
    assert len(payload["card6"]["allowed"]) == 3
    withheld = {p.id for p in v2.CARD6_BLOCKED}
    sent = " ".join(text for text, _ in stand_in._inner.sent)
    goldens = {s: v2.load_golden(s) for s in v2.SOURCES}
    for pick in v2.CARD6_BLOCKED:
        row = next(r for r in goldens[pick.source] if r["id"] == pick.id)
        assert row["content"] not in sent, pick.id
    assert withheld  # (the three rows the offline run does show)
    page = render_v2.pages(payload)["card-6-bias.html"]
    assert "Offline only" in page and render_v2.OFFLINE_ONLY_NOTE.split(":")[0][:20] in page


async def test_an_offline_run_still_shows_the_blocked_column():
    payload = await full_run()
    assert payload["card6"]["blocked_offline_only"] is False
    assert len(payload["card6"]["blocked"]) == 3
