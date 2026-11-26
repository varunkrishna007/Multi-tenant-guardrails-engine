"""The deterministic checks of a check (M3-01; design §Runtime evaluation flow, AC-G1).

They run in the Guard Service after the size bound and before redaction, rendering and the
model call, and they never depend on the model:

* **Tool arguments' schema** (``tool_call`` only, M3-03): the content is
  ``{"tool": <name>, "arguments": {...}}`` (``args`` accepted as a deprecated alias); when
  the tool's registry entry holds a JSON Schema for the arguments, the ``arguments`` member
  is validated against it **first**, and a failure is a ``block``, rule ``tool_schema``, with
  no model call (:func:`check_tool_schema`, :mod:`.tool_schema`).
* **Tool allow-list** (``tool_call`` and ``plan``): a call for a tool outside the guard
  point's ``tool_allowlist`` is a ``block``. With an allow-list configured, a check that
  names no tool is blocked too (nothing says the call is allowed). At ``tool_call`` the tool
  checked is ``CheckContext.tool``, which must be **the tool the runtime will actually
  execute** (the SDK sets it). At ``plan`` (M3-03) the allow-list is the ``plan``
  guard point's own, and the tools judged are the ones **the plan names**, extracted by
  :func:`plan_tool_names`; this check runs before the model is called.
* **Tool mismatch** (``tool_call`` only, floor): content that is a JSON object naming a
  different tool (its top-level ``"tool"``, the same member of the contract above) than
  ``CheckContext.tool`` is a
  ``block``, rule ``tool_mismatch`` (:func:`check_tool_mismatch`).
* **Deny patterns** (tenant, RE2): each of the bundle's ``deterministic.deny_patterns`` is
  matched against the **content** as submitted (before PII redaction) at every enabled guard
  point. The pattern's ``action``:

  ``block``     the content is not released, and **no model call is made** (AC-G1);
  ``escalate``  the model still runs and the more severe result wins;
  ``redact``    each match is replaced by ``[REDACTED]`` in the content **and every context
                section** before rendering (applied by :func:`redact_deny_patterns`, together
                with PII redaction);
  ``log``       recorded only.

* **Cross-tenant identifiers** (floor, ``tool_result`` and ``output``): any other tenant's
  identifier in the content is a ``block`` that no tenant can disable
  (:class:`CrossTenantScanner`, over the :class:`OtherTenantIdentifiers` port).
* **Credentials in a known format** (floor, ``plan``, ``tool_call``, ``tool_result`` and
  ``output``, the guard points of ``p__secret``; M7-01): a key, token, private-key block or
  URL with a password in the content is a ``block`` that no tenant can disable, reported as
  rule ``p__secret`` with kind ``secret_format`` and no model call
  (:func:`check_secrets`, :mod:`guardrail_engine.deterministic.secret_formats`). At ``input``
  the same credentials are replaced by ``[SECRET]`` before rendering instead (reported as a
  ``redact`` hit with the same rule id); the model question ``p__secret`` stays for every
  other format.

Every rule that fires is reported as a :class:`DeterministicHit`: its id, kind, action, layer
and a count. **Never the matched text, a position or a length**, and the cross-tenant scan
doesn't say whose identifier matched.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Callable, Hashable, Mapping, Sequence
from dataclasses import dataclass

from guardrail_engine.deterministic.identifiers import OtherTenantIdentifiers
from guardrail_engine.deterministic.regex import RegexEngine, RegexSet
from guardrail_engine.deterministic.rules import (
    CROSS_TENANT_RULE,
    REDACTION_PLACEHOLDER,
    SECRET_RULE,
    SIZE_LIMIT_RULE,
    TOOL_ALLOWLIST_RULE,
    TOOL_MISMATCH_RULE,
    TOOL_SCHEMA_RULE,
    DenyRule,
    DeterministicAction,
    DeterministicKind,
    GuardPointChecks,
)
from guardrail_engine.deterministic.secret_formats import SecretDetector
from guardrail_engine.guard.tool_schema import call_valid
from guardrail_engine.guard.verdict import DeterministicHit

CROSS_TENANT_GUARD_POINTS = frozenset({"tool_result", "output"})
"""Where the cross-tenant scan runs (backlog M3-01)."""

logger = logging.getLogger(__name__)

_TOOL_KEY = "tool"


def check_secrets(detector: SecretDetector, content: str) -> DeterministicHit | None:
    """M7-01: the floor ``block`` when ``content`` holds a credential in a known format
    (:mod:`guardrail_engine.deterministic.secret_formats`), else None. Run at the guard points
    of ``p__secret``; the count is how many were found."""
    if not (count := detector.count(content)):
        return None
    return DeterministicHit(
        rule=SECRET_RULE,
        kind=DeterministicKind.SECRET_FORMAT,
        action=DeterministicAction.BLOCK,
        layer="floor",
        count=count,
    )


def secret_redaction_hit(count: int) -> DeterministicHit:
    """M7-01: the record that ``count`` credentials were replaced by ``[SECRET]``."""
    return DeterministicHit(
        rule=SECRET_RULE,
        kind=DeterministicKind.SECRET_FORMAT,
        action=DeterministicAction.REDACT,
        layer="floor",
        count=count,
    )


def size_limit_hit() -> DeterministicHit:
    return DeterministicHit(
        rule=SIZE_LIMIT_RULE,
        kind=DeterministicKind.SIZE_LIMIT,
        action=DeterministicAction.BLOCK,
        layer="floor",
    )


def check_tool_allowlist(checks: GuardPointChecks, tool: str | None) -> DeterministicHit | None:
    """The allow-list's hit when ``tool`` isn't allowed (or isn't named), else None."""
    if checks.tool_allowlist is None or (tool is not None and tool in checks.tool_allowlist):
        return None
    return DeterministicHit(
        rule=TOOL_ALLOWLIST_RULE,
        kind=DeterministicKind.TOOL_ALLOWLIST,
        action=DeterministicAction.BLOCK,
        layer="tenant",
    )


def check_tool_schema(schema: object, content: str) -> DeterministicHit | None:
    """M3-03: the schema hit when the tool call's **arguments** (the ``arguments`` member of
    ``content``, or its deprecated alias ``args``) don't satisfy the tool's registry schema,
    else None. ``schema`` None means the tool has no schema: nothing is validated. Strict
    about what the tool would receive (no duplicate keys, ``NaN`` or non-JSON content, no
    ``arguments`` member, both ``arguments`` and ``args``); never raises, and a schema the
    validator can't read fails the call."""
    if schema is None or call_valid(schema, content):
        return None
    return DeterministicHit(
        rule=TOOL_SCHEMA_RULE,
        kind=DeterministicKind.TOOL_SCHEMA,
        action=DeterministicAction.BLOCK,
        layer="tenant",
    )


class _Obj(list):  # type: ignore[type-arg]
    """A JSON object as its ``(key, value)`` pairs, in order, duplicate keys kept."""


PLAN_TOOL_KEYS = frozenset({"tool", "tool_name", "toolName", "Tool", "TOOL_NAME", "recipient_name"})
"""Members whose value is **one** tool's name, at any depth of the plan JSON: a string is a
name, ``null`` names nothing, and anything else is an unreadable name."""
PLAN_TOOL_LIST_KEYS = frozenset({"tools", "tool_names"})
"""Members whose value is a name, or a list of tools: each string is a name, and each object
must name its tool (see :func:`plan_tool_names`)."""
PLAN_CALL_LIST_KEYS = frozenset({"tool_calls"})
"""Members whose value is a list of invocations: every element must name its tool."""
PLAN_INVOCATION_TYPES = frozenset({"function", "tool_use", "tool", "tool_call", "function_call"})
"""A ``type`` member with one of these values (compared case-insensitively) marks an object as a
tool invocation."""
PLAN_ARGUMENT_KEYS = frozenset({"arguments", "input", "parameters"})
"""An object with a ``name`` member and one of these is an invocation, with or without a
``type`` (hand-rolled planners emit ``{"name": ..., "arguments": {...}}``)."""


def _invocation_names(pairs: list[tuple[str, object]]) -> list[str] | None:
    """The tool names one invocation-looking object states, or None when it states none that
    can be read: ``function.name`` (OpenAI), ``name`` (Anthropic ``tool_use``, a ``tools[]``
    entry), or one of the single-name members."""
    names: list[str] = []
    for key, value in pairs:
        if isinstance(value, str) and (key == "name" or key in PLAN_TOOL_KEYS):
            names.append(value)
        elif key in ("function", "function_call") and isinstance(value, _Obj):
            names.extend(v for k, v in value if k == "name" and isinstance(v, str))
        elif key == "action" and isinstance(value, str):
            names.append(value)
    return names or None


def plan_tool_names(content: str) -> tuple[str, ...] | None:
    """The tools a plan names, or None when that can't be told (M3-03, widened later).

    **How they are extracted.** The plan is the agent's plan **as JSON**. It is parsed
    (duplicate keys kept, so ``{"tool": "a", "tool": "b"}`` names both), then **every object
    at any depth is walked**. Each of these is read, and each shape has a test:

    * ``"tool"``, ``"tool_name"``, ``"toolName"``, ``"Tool"``, ``"TOOL_NAME"``,
      ``"recipient_name"`` (OpenAI Assistants): a string is a tool name;
      ``null`` names nothing; any other value is an unreadable name (None);
    * ``"action"``: a string is read as a tool name (a plan that uses ``action`` for
      something else needs those values on the allow-list, or another key);
    * ``"function"`` / ``"function_call"`` holding an object (OpenAI: ``{"type": "function",
      "function": {"name": ...}}``): its ``name`` must be a string, else the plan is
      unreadable; a string value is a name;
    * an object whose ``"type"`` is ``function``, ``tool_use``, ``tool``, ``tool_call`` or
      ``function_call`` (any case; Anthropic ``{"type": "tool_use", "name": ...}``), or that
      has a ``"name"`` together with ``"arguments"``, ``"input"`` or ``"parameters"``: it
      **looks like an invocation**, so it must state a tool name (``name``, ``function.name``
      or one of the members above), else the plan is unreadable;
    * ``"tool_calls"`` (a list) and ``"tools"`` (a list or one string), and ``"tool_names"``:
      each string element is a name; each object element must state its tool the same way
      (``name``, ``function.name`` and so on), else the plan is unreadable. Everything else
      in them is walked like the rest of the plan.

    Names are compared exactly, case included. A plan that names no tool gives ``()``. A plan
    that isn't JSON, is nested too deeply to parse, or has an unreadable name gives **None**,
    and the allow-list check treats that as a failure: an allow-list that can't see what a
    plan intends to call can't vouch for it.

    **A JSON plan is required** for a plan allow-list. A prose plan can't be read, so with an
    allow-list configured it is **refused**; integrators must have the planner emit JSON
    (the SDK says so). Without an allow-list the plan isn't parsed at all.

    **What it does not see.** A tool named under any other key, or in prose inside a JSON
    string, isn't extracted. The model still reads the whole plan (this check runs first and
    doesn't replace it), and the ``tool_call`` guard checks the tool that is really executed."""
    try:
        parsed = json.loads(content, object_pairs_hook=_Obj)
    except (ValueError, RecursionError):
        return None
    names: list[str] = []
    stack: list[object] = [parsed]
    while stack:  # iterative: a deep plan can't exhaust the stack
        node = stack.pop()
        if isinstance(node, list) and not isinstance(node, _Obj):
            stack.extend(node)
            continue
        if not isinstance(node, _Obj):
            continue
        if _walk_object(node, names, stack) is None:
            return None
    return tuple(names)


def _walk_object(node: _Obj, names: list[str], stack: list[object]) -> bool | None:
    """Reads one plan object; pushes what is left to walk. None: an unreadable name."""
    types = [v.lower() for k, v in node if k == "type" and isinstance(v, str)]
    keys = {k for k, _ in node}
    if any(t in PLAN_INVOCATION_TYPES for t in types) or (
        "name" in keys and keys & PLAN_ARGUMENT_KEYS
    ):
        found = _invocation_names(node)
        if found is None:
            return None  # looks like an invocation, but names no tool
        names.extend(found)
    for key, value in node:
        if key in PLAN_TOOL_KEYS:
            if isinstance(value, str):
                names.append(value)
            elif value is not None:
                return None
        elif key == "action" and isinstance(value, str):
            names.append(value)
        elif key in ("function", "function_call"):
            if isinstance(value, str):
                names.append(value)
            elif isinstance(value, _Obj):
                fn = [v for k, v in value if k == "name"]
                if not fn or not all(isinstance(v, str) for v in fn):
                    return None
                names.extend(fn)
                stack.append(value)
            else:
                stack.append(value)
        elif key in PLAN_LISTS:
            if isinstance(value, str) and key in PLAN_TOOL_LIST_KEYS:
                names.append(value)
            elif isinstance(value, list) and not isinstance(value, _Obj):
                for item in value:
                    if isinstance(item, str):
                        if key in PLAN_TOOL_LIST_KEYS:
                            names.append(item)
                    elif isinstance(item, _Obj):
                        found = _invocation_names(item)
                        if found is None:
                            return None
                        names.extend(found)
                        stack.append(item)
                    else:
                        stack.append(item)
            else:
                stack.append(value)
        else:
            stack.append(value)
    return True


PLAN_LISTS = PLAN_TOOL_LIST_KEYS | PLAN_CALL_LIST_KEYS


def check_plan_allowlist(checks: GuardPointChecks, content: str) -> DeterministicHit | None:
    """M3-03: the allow-list's hit when the plan names a tool outside the ``plan`` guard
    point's allow-list, or when the tools it names can't be told (:func:`plan_tool_names`).
    None when there is no allow-list (the plan isn't even parsed), or every tool named is on
    it."""
    allowed = checks.tool_allowlist
    if allowed is None:
        return None
    names = plan_tool_names(content)
    if names is not None and all(name in allowed for name in names):
        return None
    return DeterministicHit(
        rule=TOOL_ALLOWLIST_RULE,
        kind=DeterministicKind.TOOL_ALLOWLIST,
        action=DeterministicAction.BLOCK,
        layer="tenant",
    )


def check_tool_mismatch(content: str, tool: str | None) -> DeterministicHit | None:
    """The tool the content *names* must be the tool the check *says*.

    The allow-list judges ``CheckContext.tool`` while the model judges the content, and the
    content may name a different tool. So when ``content`` is a JSON object with a top-level
    ``"tool"`` member, every such member must be exactly ``tool``: any other value (another
    name, a non-string, or a duplicate key that differs) is a ``block``, rule
    ``tool_mismatch``, at every ``tool_call`` check. Only ``"tool"`` is compared, never
    ``"name"``, which is a common argument key. Nothing is checked when ``tool`` is None
    (the allow-list already blocks that where one is set) or when the content isn't a JSON
    object."""
    if tool is None or not content.lstrip().startswith("{"):
        return None
    try:
        pairs = json.loads(content, object_pairs_hook=_Obj)
    except (ValueError, RecursionError):  # not JSON: nothing to compare
        return None
    if all(value == tool for key, value in pairs if key == _TOOL_KEY):
        return None
    return DeterministicHit(
        rule=TOOL_MISMATCH_RULE,
        kind=DeterministicKind.TOOL_MISMATCH,
        action=DeterministicAction.BLOCK,
        layer="floor",
    )


def scan_deny_patterns(checks: GuardPointChecks, content: str) -> list[DeterministicHit]:
    """The hits of the deny patterns whose action is ``block``, ``escalate`` or ``log``, in
    the bundle's order. ``redact`` patterns are applied later, by
    :func:`redact_deny_patterns`."""
    hits = []
    for rule in checks.deny_rules:
        if rule.action is DeterministicAction.REDACT:
            continue
        if count := len(rule.regex.spans(content)):
            hits.append(_deny_hit(rule, count))
    return hits


def redact_deny_patterns(rules: Sequence[DenyRule], text: str) -> tuple[str, Mapping[str, int]]:
    """``text`` with every match of every ``redact`` rule replaced by the placeholder, and the
    matches counted per rule id. Overlapping matches (of one rule or of several) become one
    placeholder; each match still counts for its rule. Returns ``text`` itself when nothing
    matched."""
    spans: list[tuple[int, int]] = []
    counts: dict[str, int] = {}
    for rule in rules:
        if rule.action is not DeterministicAction.REDACT:
            continue
        found = rule.regex.spans(text)
        if found:
            counts[rule.id] = counts.get(rule.id, 0) + len(found)
            spans.extend(found)
    if not spans:
        return text, {}
    spans.sort()
    pieces: list[str] = []
    pos = 0
    start, end = spans[0]
    for s, e in spans[1:]:
        if s < end:
            end = max(end, e)
            continue
        pieces += (text[pos:start], REDACTION_PLACEHOLDER)
        pos = end
        start, end = s, e
    pieces += (text[pos:start], REDACTION_PLACEHOLDER, text[end:])
    return "".join(pieces), counts


def redact_hits(rules: Sequence[DenyRule], counts: Mapping[str, int]) -> list[DeterministicHit]:
    """The hits of the ``redact`` rules that replaced something, in the bundle's order."""
    return [_deny_hit(rule, counts[rule.id]) for rule in rules if counts.get(rule.id)]


def _deny_hit(rule: DenyRule, count: int) -> DeterministicHit:
    return DeterministicHit(
        rule=rule.rule_id,
        kind=DeterministicKind.DENY_PATTERN,
        action=rule.action,
        layer="tenant",
        count=count,
    )


MAX_STALE_S = 30.0
"""How long the scanner serves its previous set while the source's version has moved on
before a check waits for the rebuild instead."""
RETRY_AFTER_FAILURE_S = 1.0
"""After a background rebuild fails, the least time before the next attempt."""
SHARD_TENANTS = 256
"""Tenants per compiled set when the one combined set can't be built."""


@dataclass(frozen=True, slots=True)
class _Shard:
    """One compiled set and who owns each of its patterns, by index."""

    matcher: RegexSet
    owners: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _ScanSet:
    """Every (undropped) tenant's patterns, compiled as one shard or, when the engine
    couldn't build that, as several (``sharded``)."""

    version: Hashable
    shards: tuple[_Shard, ...]
    dropped: tuple[str, ...]
    sharded: bool = False


class CrossTenantScanner:
    """Scans content for other tenants' identifiers (floor, deterministic).

    **One global set.** The :class:`OtherTenantIdentifiers` source reports a version
    on every call; when it changes, the scanner fetches every tenant's patterns and compiles
    **one** RE2 set of all of them, with an index-to-tenant map. A check matches that set and
    ignores the indexes the caller itself owns, so the cost per check doesn't depend on how
    many tenants are active.

    **A bad tenant is dropped, not everyone blocked.** Each tenant's patterns are
    compiled on their own first. A tenant whose patterns fail to compile is left out of the
    set, and ``on_dropped(tenant_id)`` is called once per rebuild for it (the Guard Service
    logs a fixed-word alert and meters it). Its identifiers are then **not scanned for** until
    the source's version changes and they compile, which is why registration refuses such a
    pattern in the first place (``validate_identifier_pattern``). The other tenants' checks
    are not affected.

    **A combined set too big to build is sharded, not fatal.** Patterns that each
    compile, and compile together with one tenant's, can still be too much for the engine in
    **one** set (its memory bound). Then the scanner matches over chunks of
    :data:`SHARD_TENANTS` tenants instead; a chunk the engine can't build either is matched
    through its tenants' own sets, which were compiled in the first step. ``on_sharded()`` is
    called once per rebuild (the Guard Service logs a fixed-word alert and pages a warning),
    and the sharded set is the built set: the next check doesn't try the combined one again
    until the source's version changes. A check matches every shard and still ignores the
    caller's own patterns, so a cross-tenant match blocks and a clean check allows exactly as
    with one set; it costs one match per shard.

    **A rebuild never stalls a check.** The first build is waited for: there is nothing
    to scan with before it. After that, when the source's version moves, the scanner starts the
    rebuild in the background and goes on matching the **previous** set, which swaps out when
    the new one is built. The previous set is stale for the seconds the rebuild takes, and
    only for what changed (a newly registered identifier, a tenant added or taken out). If a
    rebuild has not landed :data:`MAX_STALE_S` after the scanner first saw the new version, the
    next check waits for one instead, and fails closed if it can't be built.

    **A source whose version raises fails the check closed**: the exception propagates and the
    Guard Service answers ``internal_error``. A source whose patterns can't be read during a
    background rebuild is logged and retried; the previous set stays in use until
    :data:`MAX_STALE_S`, and after that the checks fail closed.
    """

    def __init__(
        self,
        source: OtherTenantIdentifiers,
        engine: RegexEngine,
        on_dropped: Callable[[str], None] | None = None,
        on_sharded: Callable[[], None] | None = None,
        *,
        shard_tenants: int = SHARD_TENANTS,
        max_stale_s: float = MAX_STALE_S,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if shard_tenants < 1:
            raise ValueError("shard_tenants must be at least 1")
        if max_stale_s < 0:
            raise ValueError("max_stale_s must not be negative")
        self._source = source
        self._engine = engine
        self._on_dropped = on_dropped
        self._on_sharded = on_sharded
        self._shard_tenants = shard_tenants
        self._built: _ScanSet | None = None
        self._rebuild_lock = asyncio.Lock()
        self._max_stale_s = max_stale_s
        self._clock = clock
        self._stale_since: float | None = None
        self._failed_at: float | None = None
        self._background: asyncio.Task[None] | None = None
        self._latest: Hashable = None

    @property
    def dropped_tenants(self) -> tuple[str, ...]:
        """The tenants left out of the current set because their patterns didn't compile."""
        return () if self._built is None else self._built.dropped

    @property
    def shard_count(self) -> int:
        """The compiled sets the current scan matches over: 1 normally, more when the
        combined set couldn't be built, 0 with nothing to scan for (or before the first)."""
        return 0 if self._built is None else len(self._built.shards)

    async def scan(self, tenant_id: str, content: str) -> DeterministicHit | None:
        version = await self._source.version()
        self._latest = version  # the newest version any check has seen
        built = self._built
        if built is None:
            built = await self._rebuild(version)  # nothing to serve yet: wait for the first
        elif built.version != version:
            built = await self._previous_or_rebuilt(built, version)
        for shard in built.shards:
            owners = shard.owners
            if any(owners[i] != tenant_id for i in shard.matcher.matching(content)):
                return DeterministicHit(
                    rule=CROSS_TENANT_RULE,
                    kind=DeterministicKind.CROSS_TENANT,
                    action=DeterministicAction.BLOCK,
                    layer="floor",
                )
        return None  # nothing matched, or only the caller's own identifiers

    async def wait_for_rebuild(self) -> None:
        """Returns once no background rebuild is running (for tests and orderly shutdown)."""
        while (task := self._background) is not None and not task.done():
            await asyncio.shield(task)

    async def _previous_or_rebuilt(self, previous: _ScanSet, version: Hashable) -> _ScanSet:
        """The source has moved on from ``previous``: start a rebuild in the background and
        serve ``previous`` meanwhile, unless it has been stale for too long."""
        now = self._clock()
        if self._stale_since is None:
            self._stale_since = now
        if now - self._stale_since < self._max_stale_s:
            self._start_background(version, now)
            return previous
        return await self._rebuild(version)  # too stale: wait, and fail closed if it fails

    def _start_background(self, version: Hashable, now: float) -> None:
        task = self._background
        if task is not None and not task.done():
            return  # one rebuild at a time; the next check starts another if still behind
        if self._failed_at is not None and now - self._failed_at < RETRY_AFTER_FAILURE_S:
            return
        self._background = asyncio.get_running_loop().create_task(self._rebuild_quietly(version))

    async def _rebuild_quietly(self, version: Hashable) -> None:
        try:
            await self._rebuild(version)
            self._failed_at = None
        except asyncio.CancelledError:
            raise
        except Exception:
            self._failed_at = self._clock()
            logger.exception("the cross-tenant scan's rebuild failed; the previous set stays")

    async def _clear_stale_if_newest(self, built_version: Hashable) -> None:
        """Clear the stale clock only when what was just built is the source's newest version: if it
        moved on while this built, the clock keeps running from when it first
        moved, so a stream of changes can't keep the scanner serving a stale set for ever."""
        try:
            newest = await self._source.version()
        except Exception:
            return  # can't tell: the clock keeps running
        self._latest = newest
        if newest == built_version:
            self._stale_since = None

    async def _rebuild(self, version: Hashable) -> _ScanSet:
        async with self._rebuild_lock:
            built = self._built
            if built is not None and built.version == version:
                return built  # another check rebuilt it while this one waited
            by_tenant = await self._source.patterns_by_tenant()
            loop = asyncio.get_running_loop()
            built = await loop.run_in_executor(None, self._compile, version, by_tenant)
            self._built = built
        await self._clear_stale_if_newest(built.version)
        for dropped in built.dropped:
            try:
                if self._on_dropped is not None:
                    self._on_dropped(dropped)
            except Exception:
                logger.exception("the dropped-tenant alert hook failed; ignored")
        if built.sharded:
            try:
                if self._on_sharded is not None:
                    self._on_sharded()
            except Exception:
                logger.exception("the sharded-scan alert hook failed; ignored")
        return built

    def _compile(self, version: Hashable, by_tenant: Mapping[str, Sequence[str]]) -> _ScanSet:
        own_sets: list[tuple[str, tuple[str, ...], RegexSet]] = []
        dropped: list[str] = []
        for tenant, own_patterns in sorted(by_tenant.items()):
            own = tuple(own_patterns)
            if not own:
                continue
            try:
                compiled = self._engine.compile_set(own)  # this tenant alone: does it compile?
            except Exception:
                dropped.append(tenant)
                continue
            own_sets.append((tenant, own, compiled))
        if not own_sets:
            return _ScanSet(version, (), tuple(dropped))
        try:
            return _ScanSet(version, (self._combined(own_sets),), tuple(dropped))
        except Exception:
            pass  # too big for one set: shard it
        shards: list[_Shard] = []
        for start in range(0, len(own_sets), self._shard_tenants):
            chunk = own_sets[start : start + self._shard_tenants]
            if 1 < len(chunk) < len(own_sets):  # the whole set was just tried
                try:
                    shards.append(self._combined(chunk))
                    continue
                except Exception:
                    pass  # this chunk is too big as well: its tenants' own sets
            shards.extend(_Shard(compiled, (tenant,) * len(own)) for tenant, own, compiled in chunk)
        return _ScanSet(version, tuple(shards), tuple(dropped), sharded=True)

    def _combined(self, own_sets: Sequence[tuple[str, tuple[str, ...], RegexSet]]) -> _Shard:
        """One set of these tenants' patterns together, with the owner of each index."""
        patterns = [pattern for _, own, _ in own_sets for pattern in own]
        owners = tuple(tenant for tenant, own, _ in own_sets for _ in own)
        return _Shard(self._engine.compile_set(patterns), owners)
