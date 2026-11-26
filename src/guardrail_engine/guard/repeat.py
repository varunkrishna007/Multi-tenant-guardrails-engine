"""Repeat-attempt counting (M7-03): the same blocked content is not sent to the model again.

A model's answer varies a little from call to call. A sender whose content scores near a block
threshold could resubmit it until one draw falls under, and the content would pass. This module
counts, per tenant, the checks whose verdict **blocked** a piece of content; once the same content
has been blocked :attr:`RepeatConfig.threshold` times within :attr:`RepeatConfig.window_s`, a
further submission of it is refused deterministically, with no redaction, no model call and no
provider call (the Guard Service asks :meth:`RepeatAttempts.enter` after its deterministic
checks and before anything else is spent; copies sent at the same moment go one at a time, see
:class:`RepeatAttempts`).

**Where.** At the guard points in :attr:`RepeatConfig.guard_points`, ``input`` by default: it is
where a sender resubmits. At ``plan``, ``tool_call``, ``tool_result`` and ``output`` the content
comes from the agent or its tools, and a tenant-wide key would turn one flaky block of templated
content into minutes of refusals for everyone.

**What "the same content" is.** The key is ``(tenant, guard point, tool, repeat key, bundle
hash)``. The repeat key is the SHA-256 of the content normalised (NFKC; format characters and every
``Default_Ignorable_Code_Point`` removed; case-folded; runs of whitespace collapsed), taken on the
content as submitted, so a changed space, capital or invisible character doesn't make it new
content. The bundle hash is that of the policy that decides: a published fix starts a clean
count. A reworded text is new content: **this is not a defence
against paraphrase.** The key is **not** per conversation: ``conversation_id`` is chosen by the
caller (it is a rollout control, not a security boundary), so a sender could change it on every
try, and a verified context has no subject claim to use instead. The counters are the tenant's
own: the key starts with the tenant id, and each tenant has its own bound on the keys it may hold.

**What counts.** A final verdict whose decision is ``block`` and whose reason is ``policy`` (the
model answered and fusion blocked), or whose reason is ``provider_safety`` (the provider refused
the content), whether it ended as a block or, at a guard point with an escalate-only rule, as an
escalation to a person (M7-08). Not
counted: failures of the engine or the provider (``model_failure``, ``policy_unavailable``,
capacity refusals), ``content_too_large``, ``invalid_request``, forbidden checks, and the
deterministic blocks (they are free and repeat on their own). An escalation isn't a block. A
shadow candidate's decision isn't the verdict and isn't counted.

**The refusal doesn't count and doesn't extend the window.** It is not noted, so a text can't be
kept blocked for ever by resubmitting it: when the blocks that count have aged out of the window,
the next submission goes to the model again.

**Where the counters live.** Behind :class:`RepeatAttemptStore`. The in-process
:class:`InMemoryRepeatAttempts` is per replica and is lost on restart (a sender gets a fresh count
from each replica); a store shared across service replicas can replace it (deferred, M7-10
step 5). A store that fails never changes a
verdict: the check goes on to the model as it did before this module existed.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import unicodedata
from collections import OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import NamedTuple, Protocol

from guardrail_engine.deterministic.rules import (
    REPEAT_ATTEMPT_RULE,
    DeterministicAction,
    DeterministicKind,
)
from guardrail_engine.guard.verdict import Decision, DeterministicHit, Reason, Verdict

logger = logging.getLogger(__name__)

_WHITESPACE = re.compile(r"\s+")

# Unicode Default_Ignorable_Code_Point, from DerivedCoreProperties.txt of Unicode 15.0.0 (the
# version of Python 3.12's ``unicodedata``): characters that draw nothing, so a reader and the
# model see the same text with or without them. Pinned here, not read from the interpreter, so
# the key means the same on every Python. U+2800 BRAILLE PATTERN BLANK is not in the property but
# draws as a blank: it is folded to a space.
_DEFAULT_IGNORABLE: tuple[tuple[int, int], ...] = (
    (0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C), (0x115F, 0x1160),
    (0x17B4, 0x17B5), (0x180B, 0x180F), (0x200B, 0x200F), (0x202A, 0x202E),
    (0x2060, 0x206F), (0x3164, 0x3164), (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0), (0xFFF0, 0xFFF8), (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
)  # fmt: skip
_BLANKS = {0x2800: " "}  # str.translate takes ordinals


def _ignorable(ch: str) -> bool:
    code = ord(ch)
    return any(lo <= code <= hi for lo, hi in _DEFAULT_IGNORABLE)


@dataclass(frozen=True, slots=True)
class RepeatConfig:
    threshold: int = 2
    """Blocks of the same content, within the window, after which it is refused without a model
    call. 0 turns the check off. At 2 the first retry still gets a fresh model call (a first block
    may have been a close call, or the sender may honestly resend) and the third try does not."""
    window_s: float = 900.0
    """How long a counted block keeps counting."""
    max_keys_per_tenant: int = 10_000
    """Contents one tenant may have counted at once; the oldest go first, so one tenant's
    traffic can't push another's out."""
    max_keys: int = 200_000
    """All tenants together."""
    guard_points: frozenset[str] = frozenset({"input"})
    """Where the content is counted and refused. ``input`` only for now: it is where a sender
    resubmits. At the other guard points the content comes from the agent or its tools, and a
    tenant-wide key would turn one flaky block of templated content into minutes of refusals for
    everyone. Others can be named here later."""

    def __post_init__(self) -> None:
        if self.threshold < 0 or self.window_s <= 0 or self.max_keys_per_tenant < 1:
            raise ValueError("threshold >= 0, window_s > 0 and max_keys_per_tenant >= 1")
        if self.max_keys < self.max_keys_per_tenant:
            raise ValueError("max_keys must be at least max_keys_per_tenant")
        if not self.guard_points:
            raise ValueError("guard_points must name at least one guard point (threshold 0 is off)")

    @property
    def enabled(self) -> bool:
        return self.threshold > 0


def repeat_key(content: str) -> str:
    """The key of ``content`` for counting: its normalised text, hashed. Never stored with a
    record."""
    text = unicodedata.normalize("NFKC", content).translate(_BLANKS)
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf" and not _ignorable(ch))
    text = _WHITESPACE.sub(" ", text.casefold()).strip()
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


@dataclass(frozen=True, slots=True)
class RepeatSlot:
    """What is counted: the tenant, the guard point, the tool (``tool_call``), the content, and
    the hash of the bundle that decides the check. A published fix starts a clean count, and an
    enforce candidate's blocks count only under the candidate's own hash."""

    tenant_id: str
    guard_point: str
    tool: str | None
    key: str
    bundle_hash: str = ""


def repeat_hit(count: int) -> DeterministicHit:
    """The record of a refusal: the rule's id and the number of counted blocks, never content."""
    return DeterministicHit(
        rule=REPEAT_ATTEMPT_RULE,
        kind=DeterministicKind.REPEAT_ATTEMPT,
        action=DeterministicAction.BLOCK,
        layer="floor",
        count=count,
    )


def counts_as_block(verdict: Verdict) -> bool:
    """Whether this final verdict is a block of the content that later copies of it are refused
    for (see the module text). A provider refusal counts whether it ended as a block or as an
    escalation to a person (M7-08): either way the provider has seen the text and refused it, and
    it shouldn't be sent again."""
    return verdict.reason is Reason.PROVIDER_SAFETY or (
        verdict.decision is Decision.BLOCK and verdict.reason is Reason.POLICY
    )


class RepeatAttemptStore(Protocol):
    async def blocked(self, slot: RepeatSlot, now: float) -> int:
        """How many counted blocks of ``slot`` are within the window ending at ``now``."""
        ...

    async def note_block(self, slot: RepeatSlot, now: float) -> None:
        """Count one block of ``slot`` at ``now``."""
        ...


class InMemoryRepeatAttempts:
    """In this process only. Each tenant's slots are kept apart and bounded; a slot's block times
    are pruned to the window whenever it is read or written."""

    def __init__(self, config: RepeatConfig | None = None) -> None:
        self._config = config or RepeatConfig()
        self._tenants: dict[str, OrderedDict[tuple[str, str | None, str, str], deque[float]]] = {}
        self._total = 0
        self._tick = 0
        self._newest: dict[str, int] = {}
        """Per tenant, when it last added a slot (a counter, not a clock), to break ties."""

    @property
    def size(self) -> int:
        """Slots held now, all tenants."""
        return self._total

    def _prune(self, times: deque[float], now: float) -> None:
        horizon = now - self._config.window_s
        while times and times[0] <= horizon:
            times.popleft()

    async def blocked(self, slot: RepeatSlot, now: float) -> int:
        slots = self._tenants.get(slot.tenant_id)
        if slots is None:
            return 0
        ident = (slot.guard_point, slot.tool, slot.key, slot.bundle_hash)
        times = slots.get(ident)
        if times is None:
            return 0
        self._prune(times, now)
        if not times:
            del slots[ident]
            self._total -= 1
            if not slots:
                del self._tenants[slot.tenant_id]
                self._newest.pop(slot.tenant_id, None)
            return 0
        return len(times)

    async def note_block(self, slot: RepeatSlot, now: float) -> None:
        slots = self._tenants.setdefault(slot.tenant_id, OrderedDict())
        self._tick += 1
        self._newest[slot.tenant_id] = self._tick
        ident = (slot.guard_point, slot.tool, slot.key, slot.bundle_hash)
        times = slots.get(ident)
        if times is None:
            times = slots[ident] = deque()
            self._total += 1
        else:
            slots.move_to_end(ident)
        self._prune(times, now)
        times.append(now)
        while len(slots) > self._config.max_keys_per_tenant:
            slots.popitem(last=False)
            self._total -= 1
        while self._total > self._config.max_keys:
            self._evict_oldest_of_largest()

    def _evict_oldest_of_largest(self) -> None:
        """Over the overall bound: the tenant holding the most slots gives up its oldest, so the
        tenant that fills the store pays for it. Among tenants holding equally many, the one that
        added a slot most recently pays (the one pushing the total over, not a bystander)."""
        tenant = max(self._tenants, key=lambda t: (len(self._tenants[t]), self._newest.get(t, 0)))
        self._tenants[tenant].popitem(last=False)
        self._total -= 1
        if not self._tenants[tenant]:
            del self._tenants[tenant]
            self._newest.pop(tenant, None)


class Gate(NamedTuple):
    """What :meth:`RepeatAttempts.enter` decided for one submission."""

    outcome: str
    """``go`` (send it to the model), ``refuse`` (blocked as often as the threshold allows in the
    window) or ``timeout`` (waited for the call in flight and ran out of its time)."""
    count: int = 0
    """For ``refuse``: the counted blocks."""
    owner: bool = False
    """For ``go``: this submission is the call in flight for its slot, and must :meth:`release`
    it."""
    waited: bool = False
    """The submission waited for a call in flight on its slot, so part of its time is gone."""


class RepeatAttempts:
    """The Guard Service's side: the config, the store, and the two questions it asks.

    **Single flight.** Copies of one content sent at the same moment would all read the count
    before any block was noted, and all go to the model: every one a fresh draw. So while a slot
    has no allowing outcome in the window, **one** model call per slot is in flight; the other
    submissions wait for it (within the check's time) and read the count again. If it blocked and
    the count reached the threshold they are all refused; if it blocked below the threshold, one
    more goes and the rest wait again; if it failed, one goes. Once a call on the slot **allows**,
    the slot is open for the window and nothing waits: many users sending "hi" don't queue behind
    each other. An escalation doesn't open it: content that sometimes escalates and sometimes
    blocks goes one call at a time, and its blocks count.

    **The count always comes first.** At the threshold a submission is refused whatever the open
    state: an open slot only spares the wait. A block noted on an open slot closes it again, so
    after an allow the next blocks go back through single flight. The table of calls in flight
    holds one entry per slot being decided, so it is as large as the checks in flight; the open
    table is one table for all tenants (bounded by ``max_keys``), so one tenant's distinct
    allowed contents can push out another's open entries, which costs that tenant's first-time
    duplicates a wait, never a refusal or a pass."""

    def __init__(
        self, config: RepeatConfig | None = None, store: RepeatAttemptStore | None = None
    ) -> None:
        self.config = config or RepeatConfig()
        self._store = store or InMemoryRepeatAttempts(self.config)
        self._flights: dict[RepeatSlot, asyncio.Event] = {}
        self._open: OrderedDict[RepeatSlot, float] = OrderedDict()
        """Slots a model call has allowed, until when. Bounded like the store."""

    @property
    def enabled(self) -> bool:
        return self.config.enabled

    @property
    def in_flight(self) -> int:
        return len(self._flights)

    def applies_to(self, guard_point: str) -> bool:
        return self.config.enabled and guard_point in self.config.guard_points

    def slot(
        self,
        tenant_id: str,
        guard_point: str,
        tool: str | None,
        content: str,
        bundle_hash: str = "",
    ) -> RepeatSlot:
        return RepeatSlot(tenant_id, guard_point, tool, repeat_key(content), bundle_hash)

    async def refusal(self, slot: RepeatSlot, now: float) -> int | None:
        """The number of counted blocks when ``slot`` is to be refused, else None. Never raises:
        a store that fails means no refusal."""
        try:
            count = await self._store.blocked(slot, now)
        except Exception:
            logger.exception("the repeat-attempt store could not be read; the check goes on")
            return None
        return count if count >= self.config.threshold else None

    async def enter(self, slot: RepeatSlot, clock: Callable[[], float], wait_s: float) -> Gate:
        """Decide whether this submission may go to the model. Waits, for at most ``wait_s``, for a
        call in flight on the same slot. Never raises; a store that fails means no gating."""
        deadline = clock() + wait_s
        waited = False
        while True:
            now = clock()
            try:
                count = await self._store.blocked(slot, now)
            except Exception:
                logger.exception("the repeat-attempt store could not be read; the check goes on")
                return Gate("go", waited=waited)
            if count >= self.config.threshold:
                return Gate("refuse", count, waited=waited)  # first, whatever the open state
            if self._open.get(slot, 0.0) > now:
                return Gate("go", waited=waited)
            flight = self._flights.get(slot)
            if flight is None:
                self._flights[slot] = asyncio.Event()
                return Gate("go", owner=True, waited=waited)
            left = deadline - clock()
            if left <= 0:
                return Gate("timeout", waited=True)
            waited = True
            try:
                await asyncio.wait_for(flight.wait(), left)
            except TimeoutError:
                return Gate("timeout", waited=True)

    def release(self, slot: RepeatSlot, clock: Callable[[], float], *, allowed: bool) -> None:
        """The call in flight on ``slot`` is over: wake the submissions waiting for it. If it
        **allowed** the content (an escalation is not an allow), the slot is open for the window.
        Never raises."""
        event = self._flights.pop(slot, None)
        if allowed:
            now = clock()
            self._open[slot] = now + self.config.window_s
            self._open.move_to_end(slot)
            while len(self._open) > self.config.max_keys or (
                self._open and next(iter(self._open.values())) <= now
            ):
                self._open.popitem(last=False)
        if event is not None:
            event.set()

    def detail(self, count: int) -> str:
        """The refusal's reason, in the engine's words: no content, no key."""
        minutes = max(1, round(self.config.window_s / 60))
        return f"this content was blocked {count} times in the last {minutes} minutes"

    async def note(self, slot: RepeatSlot, now: float) -> None:
        """Count one block, and close the slot if an allow had opened it. Never raises."""
        self._open.pop(slot, None)
        try:
            await self._store.note_block(slot, now)
        except Exception:
            logger.exception("the repeat-attempt store could not be written")
