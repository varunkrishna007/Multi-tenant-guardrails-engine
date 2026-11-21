"""M3-05: the streaming ``output`` window. Offline: the checker is a stub or an engine with
the fake model. Fixtures are ordinary prose."""

from __future__ import annotations

import asyncio
import json
import secrets
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from guardrail_engine.decision import FakeDecisionModel
from guardrail_engine.guard.verdict import Decision, Reason, Verdict
from guardrail_engine.sdk import (
    MESSAGES,
    FailureReason,
    Guard,
    GuardContext,
    SentenceSplitter,
    StreamWindow,
)

SIGNED = "v1.signed-context-sentinel"
REFUSAL = "Sorry, I can't share that here."
ROOT = Path(__file__).resolve().parents[2]


def verdict(decision=Decision.ALLOW, reason=Reason.POLICY, **fields) -> Verdict:
    return Verdict(
        request_id=fields.pop("request_id", "req-1"),
        tenant_id="t_1042",
        guard_point="output",
        decision=decision,
        reason=reason,
        checked_at=datetime.now(UTC),
        latency_ms=1.0,
        **fields,
    )


class OutputChecker:
    """Answers each ``output`` check by a function of the window text; records the calls."""

    def __init__(self, decide=lambda text: verdict(), *, log: list[str] | None = None) -> None:
        self.decide = decide
        self.calls: list[tuple[str, str, str | None]] = []
        self.log = log if log is not None else []

    async def check(self, ctx, guard_point, content):
        self.calls.append((guard_point, content, ctx.request_id))
        self.log.append(f"check:{content.strip()}")
        return self.decide(content)

    @property
    def windows(self) -> list[str]:
        return [c for _, c, _ in self.calls]


class Source:
    """An async stream of chunks that records whether it was closed."""

    def __init__(self, chunks: list[str], *, log: list[str] | None = None) -> None:
        self.chunks = chunks
        self.closed = False
        self.read = 0
        self.log = log

    def __aiter__(self):
        return self._gen()

    async def _gen(self):
        try:
            for c in self.chunks:
                self.read += 1
                yield c
        finally:
            self.closed = True


class ClosableSource:
    """The iterator itself is what gets closed (an async generator)."""

    def __init__(self, chunks: list[str]) -> None:
        self.closed = False
        self._chunks = chunks

    def stream(self):
        async def gen():
            try:
                for c in self._chunks:
                    yield c
            finally:
                self.closed = True

        return gen()


async def run(guard, source, ctx=None, **kw):
    ctx = ctx or GuardContext(SIGNED)
    kw.setdefault("gate", None)  # ``gate`` is required: None = no input guard started
    return [e async for e in guard.stream_output(source, ctx, **kw)]


def block_containing(marker: str):
    return lambda text: (
        verdict(Decision.BLOCK, Reason.POLICY) if marker in text else verdict(Decision.ALLOW)
    )


# ------------------------------------------------------------------ the splitter


def split(chunks, *, max_chars=1_000, window=StreamWindow.SENTENCE):
    s = SentenceSplitter(window, max_chars)
    out: list[str] = []
    for c in chunks:
        out += s.feed(c)
    return out + s.flush()


@pytest.mark.parametrize(
    "text, windows",
    [
        ("Hello world. How are you? Fine!", ["Hello world. ", "How are you? ", "Fine!"]),
        ("Pi is 3.14 today. Next one.", ["Pi is 3.14 today. ", "Next one."]),
        ("See example.com for more. Thanks.", ["See example.com for more. ", "Thanks."]),
        ("Dr. Smith arrived. He sat down.", ["Dr. Smith arrived. ", "He sat down."]),
        ("Use fruit, e.g. apples. Then eat.", ["Use fruit, e.g. apples. ", "Then eat."]),
        ("J. R. Smith wrote it. Good.", ["J. R. Smith wrote it. ", "Good."]),
        ("We moved to the U.S. in May. Fine.", ["We moved to the U.S. in May. ", "Fine."]),
        ("1. First item\n2. Second item", ["1. First item\n2. Second item"]),
        ("He left. then he came back. Done.", ["He left. then he came back. ", "Done."]),
        ("Wait... what? Yes.", ["Wait... what? ", "Yes."]),
        ('She said "stop." Then left. End', ['She said "stop." ', "Then left. ", "End"]),
        ("(It was late.) We left. Bye", ["(It was late.) ", "We left. ", "Bye"]),
        ("First para\n\nSecond para", ["First para\n\n", "Second para"]),
        ("Title.\nthen text", ["Title.\n", "then text"]),
        ("你好。再见。", ["你好。", "再见。"]),
        ("No terminator at all", ["No terminator at all"]),
        ("Ends with a space. ", ["Ends with a space. "]),
    ],
)
def test_sentence_splitting_rules(text, windows):
    assert split([text]) == windows
    assert "".join(windows) == text  # the windows are the text, exactly


@pytest.mark.parametrize(
    "text",
    [
        "Hello world. How are you? Fine! Dr. Smith said 3.14 is close. Then he left.\n\nBye now",
        'She said "stop." Then left. (Really.) Yes! 你好。再见。 Done',
        "Wait... what? He left. then he came back. End.",
    ],
)
def test_chunking_does_not_change_the_windows(text):
    """The same windows come out however the stream is chunked, one character at a time
    included."""
    whole = split([text])
    assert split(list(text)) == whole
    assert split([text[:7], text[7:20], text[20:]]) == whole
    assert "".join(whole) == text


def test_the_final_partial_window_is_flushed_and_whitespace_alone_is_not():
    s = SentenceSplitter(StreamWindow.SENTENCE, 1_000)
    assert s.feed("One sentence. And a part") == ["One sentence. "]
    assert s.flush() == ["And a part"]
    s = SentenceSplitter(StreamWindow.SENTENCE, 1_000)
    assert s.feed("Done.  \n ") == []  # held until the next word, or the end
    assert s.flush() == ["Done.  \n "]
    assert split(["   \n  "]) == []


def test_a_sentence_end_waits_for_the_next_word_before_it_is_cut():
    """Lookahead: the next word decides ("vs. the" continues), so nothing is cut early."""
    s = SentenceSplitter(StreamWindow.SENTENCE, 1_000)
    assert s.feed("It was this vs.") == []
    assert s.feed(" that.") == []
    assert s.feed(" Next") == ["It was this vs. that. "]


def test_no_window_exceeds_the_limit():
    text = "word " * 500
    windows = split([text], max_chars=100)
    assert all(len(w) <= 100 for w in windows) and "".join(windows) == text
    long_sentence = "x" * 450  # no whitespace to cut at: cut at the limit
    windows = split([long_sentence], max_chars=100)
    assert [len(w) for w in windows] == [100, 100, 100, 100, 50]
    mixed = "Short one. " + "y " * 200 + "End."
    assert all(len(w) <= 60 for w in split([mixed], max_chars=60))


def test_full_mode_is_one_window_at_the_end_of_the_stream():
    s = SentenceSplitter(StreamWindow.FULL, 10)
    assert s.feed("A sentence. Another sentence. ") == []
    assert s.flush() == ["A sentence. Another sentence. "]


def test_the_limit_must_be_positive():
    with pytest.raises(ValueError):
        SentenceSplitter(StreamWindow.SENTENCE, 0)


# ------------------------------------------------------------------ release only on allow


async def test_every_window_is_checked_at_output_and_released_in_order():
    checker = OutputChecker()
    events = await run(Guard(checker), Source(["Hello the", "re. How are ", "you? Fine."]))
    assert [e.text for e in events] == ["Hello there. ", "How are you? ", "Fine."]
    assert all(e.released and e.result.released for e in events)
    assert [e.index for e in events] == [0, 1, 2]
    assert [c[0] for c in checker.calls] == ["output"] * 3  # one check per window
    assert checker.windows == [e.text for e in events]


async def test_a_window_is_released_only_after_its_check_and_the_next_is_not_checked_early():
    log: list[str] = []
    checker = OutputChecker(log=log)
    guard = Guard(checker)
    async for e in guard.stream_output(
        Source(["One. Two. Three."]), GuardContext(SIGNED), gate=None, refusal_message=REFUSAL
    ):
        log.append(f"release:{e.text.strip()}")
    assert log == [
        "check:One.", "release:One.", "check:Two.", "release:Two.", "check:Three.",
        "release:Three.",
    ]  # fmt: skip


async def test_a_block_stops_the_stream_and_returns_the_tenants_refusal_message():
    checker = OutputChecker(block_containing("Second"))
    source = Source(["First fine one. ", "Second bad one. ", "Third one. ", "Fourth one."])
    events = await run(Guard(checker), source, refusal_message=REFUSAL)

    assert [(e.kind, e.text) for e in events] == [
        ("window", "First fine one. "),
        ("refusal", REFUSAL),
    ]
    refusal = events[-1]
    assert not refusal.released and refusal.index == 1
    assert refusal.result.decision == "block" and refusal.result.reason == "policy"
    assert checker.windows == ["First fine one. ", "Second bad one. "]  # nothing after was checked
    assert "Third one. " not in "".join(e.text for e in events)  # ... or released
    assert source.closed and source.read < 4  # the stream was stopped and closed


async def test_a_blocked_first_window_releases_nothing():
    events = await run(
        Guard(OutputChecker(block_containing("Bad"))),
        Source(["Bad start. And more."]),
        refusal_message=REFUSAL,
    )
    assert [(e.kind, e.text) for e in events] == [("refusal", REFUSAL)]


async def test_without_a_tenant_message_the_default_for_the_result_is_used():
    events = await run(Guard(OutputChecker(block_containing("Bad"))), Source(["Bad one."]))
    assert events[0].text == MESSAGES["policy"]


@pytest.mark.parametrize(
    "decision, reason",
    [
        (Decision.BLOCK, Reason.PROVIDER_SAFETY),
        (Decision.BLOCK, Reason.CONTRACT_VIOLATION),
        (Decision.FORBIDDEN, Reason.CONTEXT_INVALID),
        ("quarantine", Reason.POLICY),  # a decision this SDK doesn't know
    ],
)
async def test_only_allow_releases_a_window(decision, reason):
    if isinstance(decision, str):
        v = SimpleNamespace(decision=decision, reason=reason, request_id="r",
                            guard_point="output", fired=(), failure_kind=None,
                            failure_reason=None, retry_after_ms=None,
                            capacity_limited=False)  # fmt: skip
    else:
        v = verdict(decision, reason)
    checker = OutputChecker(lambda text: v)
    events = await run(Guard(checker), Source(["One. Two."]), refusal_message=REFUSAL)
    assert [(e.kind, e.text) for e in events] == [("refusal", REFUSAL)]
    assert checker.windows == ["One. "]  # the stream stopped at the first window


async def test_an_escalate_window_is_held_not_refused_and_says_so():
    """Escalate means held for review, so the SDK's hold message, not the tenant's
    refusal; the window is still withheld and the stream still stops."""
    checker = OutputChecker(lambda text: verdict(Decision.ESCALATE, Reason.POLICY))
    events = await run(Guard(checker), Source(["One. Two."]), refusal_message=REFUSAL)
    assert [(e.kind, e.text) for e in events] == [("refusal", MESSAGES["escalate"])]
    assert events[0].result.held_for_escalation and not events[0].released
    assert checker.windows == ["One. "]


async def test_an_escalating_input_verdict_is_held_too():
    guard = Guard(OutputChecker(lambda text: verdict(Decision.ESCALATE, Reason.POLICY)))
    gate = guard.start_input_guard("hi", GuardContext(SIGNED))
    events = await run(guard, Source(["One."]), gate=gate, refusal_message=REFUSAL)
    assert [(e.kind, e.text) for e in events] == [("refusal", MESSAGES["escalate"])]


async def test_a_retryable_failure_says_unavailable_not_the_tenants_refusal():
    checker = OutputChecker(lambda t: verdict(Decision.BLOCK, Reason.MODEL_FAILURE))
    events = await run(Guard(checker), Source(["One."]), refusal_message=REFUSAL)
    assert events[0].kind == "refusal" and events[0].result.retryable
    assert events[0].text == MESSAGES["retryable"]


# ------------------------------------------------------------------ end of stream, modes, ids


async def test_the_final_partial_window_is_checked_and_released_too():
    checker = OutputChecker()
    events = await run(Guard(checker), Source(["A full sentence. And a trailing frag", "ment"]))
    assert [e.text for e in events] == ["A full sentence. ", "And a trailing fragment"]
    assert checker.windows == [e.text for e in events]
    # ... and a block in the partial window is a block.
    events = await run(
        Guard(OutputChecker(block_containing("frag"))),
        Source(["A full sentence. And a trailing fragment"]),
        refusal_message=REFUSAL,
    )
    assert [e.kind for e in events] == ["window", "refusal"]


async def test_full_mode_checks_the_whole_answer_once_and_releases_it_at_the_end():
    checker = OutputChecker()
    events = await run(Guard(checker), Source(["One. ", "Two. ", "Three."]), stream_window="full")
    assert checker.windows == ["One. Two. Three."]
    assert [e.text for e in events] == ["One. Two. Three."]


async def test_an_unknown_window_mode_is_refused():
    with pytest.raises(ValueError):
        await run(Guard(OutputChecker()), Source(["x"]), stream_window="paragraph")


async def test_each_window_gets_its_own_request_id_within_the_limit():
    checker = OutputChecker()
    ctx = GuardContext(SIGNED, request_id="r" * 200)
    await run(Guard(checker), Source(["One. Two. Three."]), ctx=ctx)
    ids = [rid for _, _, rid in checker.calls]
    assert all(len(i) <= 128 for i in ids) and len(set(ids)) == 3
    assert [i[-3:] for i in ids] == ["-w0", "-w1", "-w2"]
    checker2 = OutputChecker()
    await run(Guard(checker2), Source(["One. Two."]))
    assert [rid for _, _, rid in checker2.calls] == [None, None]  # the engine generates them


async def test_a_non_text_chunk_and_a_bad_context_are_refused():
    with pytest.raises(TypeError):
        await run(Guard(OutputChecker()), Source([b"bytes"]))  # type: ignore[list-item]
    with pytest.raises(TypeError):
        Guard(OutputChecker()).stream_output(Source(["x"]), "t_1042")  # type: ignore[arg-type]


async def test_an_abandoned_stream_closes_its_source():
    src = ClosableSource(["One. ", "Two. ", "Three."])
    gen = Guard(OutputChecker()).stream_output(src.stream(), GuardContext(SIGNED), gate=None)
    first = await anext(gen)
    assert first.text == "One. "
    await gen.aclose()
    assert src.closed


async def test_a_check_that_raises_releases_nothing_and_closes_the_source():
    class Broken:
        async def check(self, ctx, guard_point, content):
            raise ConnectionError("engine unreachable")

    src = Source(["One. Two."])
    events: list = []
    with pytest.raises(ConnectionError):
        async for e in Guard(Broken()).stream_output(src, GuardContext(SIGNED), gate=None):
            events.append(e)
    assert events == [] and src.closed


# ------------------------------------------------------------------ the latency bound


async def test_a_window_whose_check_times_out_is_withheld():
    class Hangs:
        async def check(self, ctx, guard_point, content):
            await asyncio.sleep(30)

    events = await run(
        Guard(Hangs()), Source(["One. Two."]), refusal_message=REFUSAL, window_timeout_s=0.05
    )
    assert [e.kind for e in events] == ["refusal"]
    r = events[0].result
    assert not r.released and r.retryable and r.failure_reason is FailureReason.TIMEOUT
    assert events[0].text == MESSAGES["retryable"]


async def test_the_window_limit_bounds_what_one_check_sees():
    checker = OutputChecker()
    await run(Guard(checker), Source(["word " * 400]), max_window_chars=100)
    assert checker.windows and all(len(w) <= 100 for w in checker.windows)
    assert "".join(checker.windows) == "word " * 400


# ------------------------------------------------------------------ PF-9 with the gate


class SlowInput:
    """A checker whose ``input`` answer waits for the test; ``output`` answers at once."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self._input: asyncio.Future[object] = asyncio.get_running_loop().create_future()

    def answer(self, v) -> None:
        self._input.set_result(v)

    async def check(self, ctx, guard_point, content):
        self.calls.append(guard_point)
        if guard_point == "input":
            return await self._input
        return verdict()


async def test_no_window_is_checked_or_released_before_the_input_verdict():
    checker = SlowInput()
    guard = Guard(checker)
    gate = guard.start_input_guard("hello", GuardContext(SIGNED))
    streaming = asyncio.create_task(
        run(guard, Source(["One. Two."]), gate=gate, refusal_message=REFUSAL)
    )
    for _ in range(20):
        await asyncio.sleep(0)
    assert not streaming.done() and checker.calls == ["input"]  # no output check, no release

    checker.answer(verdict(Decision.ALLOW))
    events = await asyncio.wait_for(streaming, 1)
    assert [e.text for e in events] == ["One. ", "Two."]
    assert checker.calls == ["input", "output", "output"]


async def test_a_blocked_input_verdict_ends_the_stream_before_any_window():
    checker = SlowInput()
    guard = Guard(checker)
    gate = guard.start_input_guard("hello", GuardContext(SIGNED))
    streaming = asyncio.create_task(
        run(guard, Source(["One. Two."]), gate=gate, refusal_message=REFUSAL)
    )
    for _ in range(20):
        await asyncio.sleep(0)
    checker.answer(verdict(Decision.BLOCK, Reason.POLICY))
    events = await asyncio.wait_for(streaming, 1)
    assert [(e.kind, e.text) for e in events] == [("refusal", REFUSAL)]
    assert checker.calls == ["input"]  # the output was never even checked


# ------------------------------------------------------------------ through the engine


async def test_through_the_engine_a_blocked_window_stops_the_stream():
    from guardrail_engine.engine import EngineSettings, build_engine
    from guardrail_engine.guard import HmacContextVerifier, InMemoryTenantDirectory, TenantProfile
    from guardrail_engine.guard.audit import NullAuditSink
    from guardrail_engine.policy import TenantAttributes

    floor = ROOT / "floor" / "rules.json"
    settings = EngineSettings.from_mapping(
        {"environment": "test", "catalog": {"floor_files": [str(floor)]},
         "gemini": {"paid_tier": True}}
    )  # fmt: skip
    fake = FakeDecisionModel(responder=lambda t, k, q: 0.97 if "MARKER-7" in t else 0.01)
    verifier = HmacContextVerifier(secrets.token_bytes(32))
    tenants = InMemoryTenantDirectory(
        [TenantProfile.build(TenantAttributes(tenant_id="t_1042"), "insurance", slug="acme")]
    )
    engine = await build_engine(settings, verifier=verifier, tenants=tenants, model=fake,
                                audit=NullAuditSink())  # fmt: skip
    try:
        version = json.loads(floor.read_text()).get("version", 1)
        await engine.bootstrap_publish({"schema_version": 1, "tenant_id": "t_1042", "version": 1,
                                        "extends": [f"platform/floor@{version}"]})  # fmt: skip
        guard, ctx = Guard(engine), GuardContext(verifier.issue("t_1042"))
        source = Source(["Your policy covers water damage. ", "MARKER-7 now. ", "Goodbye."])
        events = await run(guard, source, ctx=ctx, refusal_message=REFUSAL)
        assert [(e.kind, e.text) for e in events] == [
            ("window", "Your policy covers water damage. "),
            ("refusal", REFUSAL),
        ]
        assert events[1].result.reason == "policy"
    finally:
        await engine.shutdown()


# ------------------------------------------------------------------ the previous window


class ContextChecker(OutputChecker):
    """Also records the conversation each window's check carried."""

    def __init__(self, decide=lambda text: verdict()) -> None:
        super().__init__(decide)
        self.conversations: list[tuple] = []

    async def check(self, ctx, guard_point, content):
        self.conversations.append(ctx.conversation)
        return await super().check(ctx, guard_point, content)


async def test_each_window_is_checked_with_the_window_released_before_it_as_context():
    from guardrail_engine.guard.request import Turn

    checker = ContextChecker()
    await run(Guard(checker), Source(["The password is next. ", "Hunter2 follows. ", "Done."]))
    assert checker.conversations[0] == ()  # the first window has nothing before it
    assert checker.conversations[1] == (Turn("assistant", "The password is next. "),)
    assert checker.conversations[2] == (Turn("assistant", "Hunter2 follows. "),)


async def test_a_violation_split_across_a_boundary_is_seen_in_the_light_of_the_context():
    """The stub blocks a window only when the context before it holds 'password is' and the
    window itself holds 'Hunter2': neither half is a violation alone."""

    class Splitting(ContextChecker):
        async def check(self, ctx, guard_point, content):
            await super().check(ctx, guard_point, content)
            earlier = " ".join(t.text for t in ctx.conversation)
            bad = "Hunter2" in content and "password is" in earlier
            return verdict(Decision.BLOCK if bad else Decision.ALLOW, Reason.POLICY)

    checker = Splitting()
    events = await run(
        Guard(checker),
        Source(["The password is next. ", "Hunter2 follows. ", "More."]),
        refusal_message=REFUSAL,
    )
    assert [(e.kind, e.text) for e in events] == [
        ("window", "The password is next. "),
        ("refusal", REFUSAL),
    ]
    assert len(checker.calls) == 2  # still one check per window


async def test_the_context_is_the_tail_of_the_released_window_and_follows_the_callers_own():
    from guardrail_engine.guard.request import Turn
    from guardrail_engine.sdk.streaming import CONTEXT_TAIL_CHARS

    long_window = "x" * 900 + "END. "
    checker = ContextChecker()
    own = (Turn("user", "hello"),)
    await run(
        Guard(checker),
        Source([long_window, "Next."]),
        GuardContext(SIGNED, conversation=own),
        max_window_chars=2_000,
    )
    carried = checker.conversations[1]
    assert carried[0] == own[0]
    assert carried[1].role == "assistant" and carried[1].text == long_window[-CONTEXT_TAIL_CHARS:]
    assert carried[1].text.endswith("END. ") and len(carried[1].text) == CONTEXT_TAIL_CHARS


async def test_a_withheld_window_is_never_carried_as_context():
    checker = ContextChecker(block_containing("Bad"))
    await run(Guard(checker), Source(["Fine. ", "Bad one. ", "Never."]))
    assert all("Bad" not in " ".join(t.text for t in c) for c in checker.conversations)


async def test_full_mode_has_no_previous_window():
    checker = ContextChecker()
    await run(Guard(checker), Source(["One. Two. Three."]), stream_window="full")
    assert checker.conversations == [()]


async def test_the_callers_context_object_is_not_changed():
    ctx = GuardContext(SIGNED, request_id="r")
    await run(Guard(ContextChecker()), Source(["One. Two."]), ctx)
    assert ctx.conversation == () and ctx.request_id == "r"


# ------------------------------------------------------------------ the arguments


@pytest.mark.parametrize("bad", [None, 0, -1, -0.5, float("inf"), float("nan"), True, "5"])
def test_a_window_timeout_that_disables_the_bound_is_refused_at_once(bad):
    guard = Guard(OutputChecker())
    with pytest.raises(ValueError, match="window_timeout_s"):
        guard.stream_output(Source(["x"]), GuardContext(SIGNED), gate=None, window_timeout_s=bad)


def test_a_positive_timeout_is_accepted():
    Guard(OutputChecker()).stream_output(
        Source(["x"]), GuardContext(SIGNED), gate=None, window_timeout_s=0.5
    )
    Guard(OutputChecker()).stream_output(
        Source(["x"]), GuardContext(SIGNED), gate=None, window_timeout_s=3
    )


@pytest.mark.parametrize("bad", [0, -3])
def test_a_window_limit_below_one_is_refused_at_once(bad):
    with pytest.raises(ValueError, match="max_window_chars"):
        Guard(OutputChecker()).stream_output(
            Source(["x"]), GuardContext(SIGNED), gate=None, max_window_chars=bad
        )
    with pytest.raises(TypeError, match="max_window_chars"):
        Guard(OutputChecker()).stream_output(
            Source(["x"]), GuardContext(SIGNED), gate=None, max_window_chars=1.5
        )


def test_the_gate_cannot_be_left_out():
    guard = Guard(OutputChecker())
    with pytest.raises(TypeError, match="gate"):
        guard.stream_output(Source(["x"]), GuardContext(SIGNED))  # type: ignore[call-arg]


async def test_only_a_gate_or_none_is_accepted():
    guard = Guard(OutputChecker())
    with pytest.raises(TypeError, match="InputGate"):
        guard.stream_output(Source(["x"]), GuardContext(SIGNED), gate=object())  # type: ignore[arg-type]
    gate = guard.start_input_guard("hi", GuardContext(SIGNED))
    events = [
        e async for e in guard.stream_output(Source(["One."]), GuardContext(SIGNED), gate=gate)
    ]
    assert [e.kind for e in events] == ["window"]


async def test_the_module_function_checks_its_options_too():
    from guardrail_engine.sdk.streaming import stream_output

    gen = stream_output(
        Guard(OutputChecker()), Source(["x"]), GuardContext(SIGNED), gate=None, window_timeout_s=-1
    )
    with pytest.raises(ValueError, match="window_timeout_s"):
        await anext(gen)
