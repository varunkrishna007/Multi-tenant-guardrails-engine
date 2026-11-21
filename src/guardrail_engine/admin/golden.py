"""Golden-set upload (M2-06): labelled examples per guard point, in tenant-scoped storage.

A golden set is **immutable**: an upload creates a new set (``gs_`` plus a random id) and a set
is never edited, so a test run or a regression gate that cites ``set_id`` and ``set_hash`` always
means the same examples. The hash covers the canonical JSON of the examples.

An upload is a JSON object ``{"name": ..., "examples": [{"id", "guard_point", "label",
"content"}]}``, read strictly (duplicate members, ``NaN`` and unknown fields are errors) and
checked whole: every problem is reported together and nothing is stored if any row fails.

* ``label`` is ``allow`` or ``block``; ``guard_point`` is one of the five; ids are unique in the
  set. Content is at most :data:`MAX_EXAMPLE_CHARS` characters, a set at most
  :data:`MAX_EXAMPLES` examples, a tenant at most :data:`MAX_SETS` sets.
* **Harm vocabulary, by quarantine** (:mod:`guardrail_engine.admin.vocabulary`; decided
  2026-11-17). The user's rule is about what reaches the provider, not what a tenant may store.
  So a row whose id or content trips the tripwire is **stored with ``quarantined`` set** and the
  upload succeeds; the response lists those rows by id and view (never the word). The test
  endpoint **never sends a quarantined row**: the store doesn't return it, and the runner checks
  again before any request. A row id that marks a harm row (``-harm-``) and any label other than
  ``allow`` or ``block`` are still refused outright.

Storage is tenant-scoped like the policy store: ``store.scoped(scope)`` returns a view for one
verified tenant, and the Postgres tables are under forced row-level security. The class A event
(who, which set, its hash and size, whether it was an operator crossing tenants) is written in
the same step as the set.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from guardrail_engine.admin.service import DraftError, DraftInvalidError, DraftServiceError
from guardrail_engine.admin.vocabulary import normalise, strings_tripwire
from guardrail_engine.authz.authorizer import AuthzDecision
from guardrail_engine.authz.model import Principal
from guardrail_engine.policy.canonical import sha256_of
from guardrail_engine.policy.json_document import parse_json_text
from guardrail_engine.policy.schema import GUARD_POINTS
from guardrail_engine.store.port import ScopeMismatchError
from guardrail_engine.tenant_scope import TenantScope

UPLOAD_GOLDEN = ("POST", "/v1/tenants/{tid}/guardrails/golden-sets")
LIST_GOLDEN = ("GET", "/v1/tenants/{tid}/guardrails/golden-sets")
GET_GOLDEN = ("GET", "/v1/tenants/{tid}/guardrails/golden-sets/{set_id}")
LABELS = ("allow", "block")
MAX_SETS = 50
ESCALATION_SET_PREFIX = "escalation-"
"""M4-05: a resolved escalation becomes a one-example set named ``escalation-<item id>``. Such
sets are made by the escalation service only (an upload may not use the prefix), don't count
against :data:`MAX_SETS` (a tenant resolving 60 items must not be locked out of uploading), have
their own cap, and are left out of the golden-set list (they would bury it); each is reachable
by its id from the item that made it."""
MAX_ESCALATION_SETS = 50_000
INCLUDE_ESCALATION = "escalation"
"""``GET golden-sets?include=escalation`` lists the escalation label sets instead."""
HASH_ONLY_VIEW = "hash_only"
"""The marker in a placeholder row's ``quarantine``: a label whose content R3 doesn't let us keep.
It is stored so the label is on record, and held back like a quarantined row (never sent, never
counted as evidence)."""
MAX_EXAMPLES = 1000
MAX_EXAMPLE_CHARS = 20_000
MAX_BODY_BYTES = 4 * 1024 * 1024
MAX_ID_CHARS = 64
MAX_NAME_CHARS = 80
SET_ID_PREFIX = "gs_"
GOLDEN_ID = re.compile(r"gs_[0-9a-f]{16}")
_EXAMPLE_FIELDS = {"id", "guard_point", "label", "content"}
_REQUEST_FIELDS = {"name", "examples"}
_NAME_ALLOWED = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ._-")


@dataclass(frozen=True, slots=True)
class GoldenExample:
    id: str
    guard_point: str
    label: str
    content: str
    quarantine: tuple[str, ...] = ()
    """The tripwire views that matched (``raw``, ``normalised``, ``base64 depth n``); empty for
    a row that may be sent. Never the matched word."""

    @property
    def quarantined(self) -> bool:
        return bool(self.quarantine)


@dataclass(frozen=True, slots=True)
class GoldenSetInfo:
    set_id: str
    name: str
    set_hash: str
    created_at: datetime
    created_by: str
    counts: dict[str, dict[str, int]] = field(default_factory=dict)
    """Per guard point, the examples by label: ``{"output": {"allow": 3, "block": 2}}``."""
    quarantined: tuple[tuple[str, tuple[str, ...]], ...] = ()
    """The quarantined rows, as ``(example id, views)``. These are never sent."""

    @property
    def total(self) -> int:
        return sum(n for by in self.counts.values() for n in by.values())

    @property
    def is_escalation_label(self) -> bool:
        return self.name.startswith(ESCALATION_SET_PREFIX)


def content_key(content: str) -> str:
    """What makes two examples the same for the evidence gate's counts: the content
    with format characters and look-alike letters normalised (as the harm tripwire reads it),
    case folded and whitespace collapsed, so ``x1`` and ``X1 `` count once. **Residual:** a
    paraphrase, a typo or a changed number is a different example; the counts prove a quantity
    of distinct strings, not coverage, which is for the precision gate (M4-01)."""
    return " ".join(normalise(content).casefold().split())


@dataclass(frozen=True, slots=True)
class GoldenPage:
    """A page of the examples a test run may send at one guard point."""

    total: int
    """Examples at the guard point that may be sent (not quarantined)."""
    quarantined: int
    """Examples at the guard point held back."""
    items: list[GoldenExample]


@dataclass(frozen=True, slots=True)
class GoldenAuditEvent:
    at: datetime
    actor: str
    tenant_id: str
    set_id: str
    set_hash: str
    examples: int
    quarantined: int = 0
    cross_tenant: bool = False
    operator: bool = False


class GoldenSetNotFoundError(DraftServiceError):
    """The tenant has no such golden set. Also raised for another tenant's set (HTTP 404)."""


class GoldenSetExistsError(DraftServiceError):
    """A set with that id is already stored (an escalation label made twice)."""


class TooManyGoldenSetsError(DraftServiceError):
    """The tenant is at :data:`MAX_SETS` (HTTP 409)."""


class GoldenStore(Protocol):
    """A tenant-scoped golden-set store. ``tenant_id`` must be the scope's tenant (else
    :class:`ScopeMismatchError`)."""

    async def create(
        self,
        tenant_id: str,
        info: GoldenSetInfo,
        examples: tuple[GoldenExample, ...],
        event: GoldenAuditEvent,
    ) -> GoldenSetInfo:
        """Store the set and its event together. Raises :class:`TooManyGoldenSetsError` when
        the tenant already has :data:`MAX_SETS` sets."""
        ...

    async def get(self, tenant_id: str, set_id: str) -> GoldenSetInfo | None: ...

    async def label_counts(self, tenant_id: str) -> dict[str, dict[str, int]]:
        """For the evidence gate (R1): per guard point, how many examples carry each label,
        over all the tenant's sets, de-duplicated by content within a guard point, leaving out
        quarantined rows and any content that carries both labels."""
        ...

    async def escalation_label_counts(self, tenant_id: str) -> dict[str, dict[str, int]]:
        """Like :meth:`label_counts`, over the sets made from resolved escalations alone (M4-05).
        The evidence gate shows it beside the total, so a tenant can see how many of its counts
        come from escalation labels."""
        ...

    async def list(self, tenant_id: str) -> list[GoldenSetInfo]:
        """The tenant's sets, oldest first."""
        ...

    async def examples(
        self, tenant_id: str, set_id: str, guard_point: str, *, offset: int, limit: int
    ) -> GoldenPage:
        """The page of examples **that may be sent** at ``guard_point`` (a quarantined row is
        never returned), in upload order, with the totals. Raises
        :class:`GoldenSetNotFoundError`."""
        ...

    async def audit_events(self, tenant_id: str) -> list[GoldenAuditEvent]: ...


class ScopedGoldenStores(Protocol):
    def scoped(self, scope: TenantScope) -> GoldenStore: ...


# --------------------------------------------------------------------------- memory store


@dataclass
class InMemoryGoldenStore:
    _sets: dict[tuple[str, str], tuple[GoldenSetInfo, tuple[GoldenExample, ...]]] = field(
        default_factory=dict
    )
    _events: list[GoldenAuditEvent] = field(default_factory=list)

    offboard_tables = ("tenant_golden_examples", "tenant_golden_sets")

    def offboard_tenant(
        self, tenant_id: str, table: str, limit: int, *, count_only: bool = False
    ) -> dict[str, int]:
        """M5-07: delete (or count) a terminated tenant's rows (see ``TenantDataHolder``)."""
        mine = [k for k in self._sets if k[0] == tenant_id]
        if table == "tenant_golden_sets":
            # A set goes only once its examples have (the database's foreign key says the same).
            empty = [k for k in mine if not self._sets[k][1]]
            if count_only:
                return {table: len(mine)}
            for k in empty[:limit]:
                del self._sets[k]
            return {table: len(empty[:limit])}
        if count_only:
            return {table: sum(len(self._sets[k][1]) for k in mine)}
        left = limit
        for k in mine:
            info, examples = self._sets[k]
            take = min(left, len(examples))
            self._sets[k] = (info, examples[take:])
            left -= take
        return {table: limit - left}

    def scoped(self, scope: TenantScope) -> GoldenStore:
        if not isinstance(scope, TenantScope):
            raise TypeError("scoped() takes a TenantScope")
        return _ScopedMemoryGolden(self, scope)


class _ScopedMemoryGolden:
    def __init__(self, store: InMemoryGoldenStore, scope: TenantScope) -> None:
        self._store = store
        self._scope = scope

    def _check(self, tenant_id: str) -> None:
        if tenant_id != self._scope.tenant_id:
            raise ScopeMismatchError()

    async def create(
        self,
        tenant_id: str,
        info: GoldenSetInfo,
        examples: tuple[GoldenExample, ...],
        event: GoldenAuditEvent,
    ) -> GoldenSetInfo:
        self._check(tenant_id)
        if event.tenant_id != tenant_id:
            raise ScopeMismatchError()
        mine = [
            k
            for k, v in self._store._sets.items()
            if k[0] == tenant_id and v[0].is_escalation_label == info.is_escalation_label
        ]
        if len(mine) >= (MAX_ESCALATION_SETS if info.is_escalation_label else MAX_SETS):
            raise TooManyGoldenSetsError()
        if (tenant_id, info.set_id) in self._store._sets:
            raise GoldenSetExistsError()
        self._store._sets[(tenant_id, info.set_id)] = (info, examples)
        self._store._events.append(event)
        return info

    async def get(self, tenant_id: str, set_id: str) -> GoldenSetInfo | None:
        self._check(tenant_id)
        found = self._store._sets.get((tenant_id, set_id))
        return None if found is None else found[0]

    async def label_counts(self, tenant_id: str) -> dict[str, dict[str, int]]:
        return await self._counts(tenant_id, escalation_only=False)

    async def escalation_label_counts(self, tenant_id: str) -> dict[str, dict[str, int]]:
        return await self._counts(tenant_id, escalation_only=True)

    async def _counts(self, tenant_id: str, *, escalation_only: bool) -> dict[str, dict[str, int]]:
        self._check(tenant_id)
        labels: dict[tuple[str, str], set[str]] = {}
        for (tid, _), (info, examples) in self._store._sets.items():
            if tid != tenant_id or (escalation_only and not info.is_escalation_label):
                continue
            for e in examples:
                if not e.quarantined:
                    labels.setdefault((e.guard_point, content_key(e.content)), set()).add(e.label)
        counts: dict[str, dict[str, int]] = {}
        for (guard_point, _), seen in labels.items():
            if len(seen) == 1:  # a content labelled both ways proves nothing
                (label,) = seen
                by = counts.setdefault(guard_point, {})
                by[label] = by.get(label, 0) + 1
        return counts

    async def list(self, tenant_id: str) -> list[GoldenSetInfo]:
        self._check(tenant_id)
        mine = [v[0] for (t, _), v in self._store._sets.items() if t == tenant_id]
        return sorted(mine, key=lambda i: (i.created_at, i.set_id))

    async def examples(
        self, tenant_id: str, set_id: str, guard_point: str, *, offset: int, limit: int
    ) -> GoldenPage:
        self._check(tenant_id)
        found = self._store._sets.get((tenant_id, set_id))
        if found is None:
            raise GoldenSetNotFoundError()
        at_point = [e for e in found[1] if e.guard_point == guard_point]
        sendable = [e for e in at_point if not e.quarantined]
        return GoldenPage(
            len(sendable), len(at_point) - len(sendable), sendable[offset : offset + limit]
        )

    async def audit_events(self, tenant_id: str) -> list[GoldenAuditEvent]:
        self._check(tenant_id)
        return [e for e in self._store._events if e.tenant_id == tenant_id]


# --------------------------------------------------------------------------- the service


def examples_hash(examples: tuple[GoldenExample, ...]) -> str:
    return sha256_of(
        [
            {"id": e.id, "guard_point": e.guard_point, "label": e.label, "content": e.content}
            for e in examples
        ]
    )


def parse_upload(body: bytes) -> tuple[str, tuple[GoldenExample, ...]]:
    """Read and check an upload, strictly and whole. Raises :class:`DraftInvalidError` with
    every problem (codes ``golden.*``)."""
    doc, problems = parse_json_text(body)
    if problems:
        raise DraftInvalidError([DraftError(str(p.code), p.path, p.message) for p in problems])
    errors: list[DraftError] = []

    def bad(code: str, path: str, message: str) -> None:
        errors.append(DraftError(f"golden.{code}", path, message))

    if not isinstance(doc, dict):
        raise DraftInvalidError([DraftError("golden.not_object", "$", "the upload is an object")])
    for extra in sorted(set(doc) - _REQUEST_FIELDS):
        bad("unknown_field", f"$.{extra}", "not a field of an upload")
    name = doc.get("name")
    if isinstance(name, str) and name.startswith(ESCALATION_SET_PREFIX):
        bad(
            "name_reserved", "$.name", f"names starting with {ESCALATION_SET_PREFIX!r} are reserved"
        )
    if (
        not isinstance(name, str)
        or not 1 <= len(name) <= MAX_NAME_CHARS
        or not set(name) <= _NAME_ALLOWED
    ):
        bad("name", "$.name", f"1 to {MAX_NAME_CHARS} letters, digits, spaces, '.', '_' or '-'")
    raw = doc.get("examples")
    rows: list[GoldenExample] = []
    if not isinstance(raw, list) or not 1 <= len(raw) <= MAX_EXAMPLES:
        bad("examples", "$.examples", f"a list of 1 to {MAX_EXAMPLES} examples")
    else:
        seen: set[str] = set()
        for i, row in enumerate(raw):
            path = f"$.examples[{i}]"
            if not isinstance(row, dict):
                bad("example", path, "an example is an object")
                continue
            for extra in sorted(set(row) - _EXAMPLE_FIELDS):
                bad("unknown_field", f"{path}.{extra}", "not a field of an example")
            eid, gp, label, content = (
                row.get(k) for k in ("id", "guard_point", "label", "content")
            )
            ok = True
            if not isinstance(eid, str) or not 1 <= len(eid) <= MAX_ID_CHARS:
                bad("id", f"{path}.id", f"text of 1 to {MAX_ID_CHARS} characters")
                ok = False
            elif eid in seen:
                bad("id", f"{path}.id", "ids must be unique in the set")
                ok = False
            else:
                seen.add(eid)
            if gp not in GUARD_POINTS:
                bad("guard_point", f"{path}.guard_point", f"one of {', '.join(GUARD_POINTS)}")
                ok = False
            if label not in LABELS:
                bad("label", f"{path}.label", f"one of {', '.join(LABELS)}")
                ok = False
            if not isinstance(content, str) or not 1 <= len(content) <= MAX_EXAMPLE_CHARS:
                bad("content", f"{path}.content", f"text of 1 to {MAX_EXAMPLE_CHARS} characters")
                ok = False
            if ok:
                if "-harm-" in eid:
                    bad("excluded", f"{path}.id", "a harm row id (user instruction, 2026-11-17)")
                # Quarantine, not refusal: stored, listed in the response, never sent.
                views = tuple(strings_tripwire(eid, content))
                rows.append(GoldenExample(eid, gp, label, content, views))
    if errors:
        raise DraftInvalidError(errors)
    return name, tuple(rows)


class GoldenService:
    def __init__(
        self,
        store: ScopedGoldenStores,
        *,
        clock: Any = lambda: datetime.now(UTC),
        id_factory: Any = lambda: SET_ID_PREFIX + secrets.token_hex(8),
        require_issuer: bool = False,
    ) -> None:
        self._require_issuer = require_issuer
        self._store = store
        self._clock = clock
        self._id_factory = id_factory

    async def upload(
        self, decision: AuthzDecision, principal: Principal, body: bytes
    ) -> GoldenSetInfo:
        from guardrail_engine.admin.service import DecisionError, _scope_of

        scope = _scope_of(decision, UPLOAD_GOLDEN)
        if self._require_issuer and principal.issuer is None:
            raise DecisionError("the principal has no issuer; the audit actor needs one")
        if len(body) > MAX_BODY_BYTES:
            raise DraftInvalidError(
                [
                    DraftError(
                        "golden.too_large", "$", f"an upload is at most {MAX_BODY_BYTES} bytes"
                    )
                ]
            )
        name, examples = parse_upload(body)
        return await self._create(scope, decision, principal, name, examples)

    async def import_examples(
        self,
        decision: AuthzDecision,
        principal: Principal,
        endpoint: tuple[str, str],
        name: str,
        rows: tuple[tuple[str, str, str, str], ...],
    ) -> GoldenSetInfo:
        """Store ``rows`` (id, guard point, label, content) as a new set for the tenant of a
        decision made for ``endpoint``: how a template's starter examples reach the golden set
        (M2-03). They go through the same harm tripwire as an upload (quarantined, never sent)
        and count against the same cap on sets."""
        from guardrail_engine.admin.service import DecisionError, _scope_of

        scope = _scope_of(decision, endpoint)
        if self._require_issuer and principal.issuer is None:
            raise DecisionError("the principal has no issuer; the audit actor needs one")
        examples = tuple(
            GoldenExample(eid, gp, label, content, tuple(strings_tripwire(eid, content)))
            for eid, gp, label, content in rows
        )
        return await self._create(scope, decision, principal, name, examples)

    async def _create(
        self,
        scope: TenantScope,
        decision: AuthzDecision,
        principal: Principal,
        name: str,
        examples: tuple[GoldenExample, ...],
        *,
        set_id: str | None = None,
    ) -> GoldenSetInfo:
        counts: dict[str, dict[str, int]] = {}
        for e in examples:
            by = counts.setdefault(e.guard_point, {})
            by[e.label] = by.get(e.label, 0) + 1
        info = GoldenSetInfo(
            set_id=set_id if set_id is not None else self._id_factory(),
            name=name,
            set_hash=examples_hash(examples),
            created_at=self._clock(),
            created_by=principal.actor,
            counts=counts,
            # By position when the match is in the id itself, so the response never echoes it.
            quarantined=tuple(
                (f"examples[{i}]" if strings_tripwire(e.id) else e.id, e.quarantine)
                for i, e in enumerate(examples)
                if e.quarantined
            ),
        )
        event = GoldenAuditEvent(
            at=info.created_at,
            actor=principal.actor,
            tenant_id=scope.tenant_id,
            set_id=info.set_id,
            set_hash=info.set_hash,
            examples=len(examples),
            quarantined=len(info.quarantined),
            cross_tenant=decision.cross_tenant,
            operator=principal.platform_operator,
        )
        return await self._store.scoped(scope).create(scope.tenant_id, info, examples, event)

    async def add_escalation_label(
        self,
        decision: AuthzDecision,
        principal: Principal,
        endpoint: tuple[str, str],
        *,
        item_id: str,
        guard_point: str,
        label: str,
        content: str | None,
        content_sha256: str | None,
    ) -> tuple[GoldenSetInfo, str]:
        """The golden label of a resolved escalation (M4-05, R3). Returns the set and its mode,
        ``content`` or ``hash_only``.

        A one-example set whose id comes from the item, so labelling an item twice finds the
        set instead of making another. ``content`` is the text to label, or None when R3 doesn't
        allow keeping it: then the row is a **placeholder** holding only the content hash,
        stored quarantined (view ``hash_only``) so it is never sent to the model and never
        counted as evidence. A row with content goes through the harm-vocabulary tripwire like
        any upload: a hit stores it quarantined and it is never sent. A ``content`` over the
        example limit is stored as a placeholder.

        Authorised against ``endpoint`` (the resolve route), which is where the actor came
        from. Class A: the set's audit event (actor, set, hash, size) is written with it."""
        from guardrail_engine.admin.service import DecisionError, _scope_of

        scope = _scope_of(decision, endpoint)
        if principal.platform_operator:  # an operator never writes a tenant's labels
            raise DecisionError("a platform operator can't write a tenant's labels")
        if self._require_issuer and principal.issuer is None:
            raise DecisionError("the principal has no issuer; the audit actor needs one")
        if label not in LABELS or guard_point not in GUARD_POINTS:
            raise DecisionError("not a label or a guard point")
        set_id = SET_ID_PREFIX + sha256_of(f"{scope.tenant_id}\x00{item_id}")[-16:]
        store = self._store.scoped(scope)
        existing = await store.get(scope.tenant_id, set_id)
        if existing is not None:
            return existing, (HASH_ONLY_VIEW if _is_placeholder(existing) else "content")
        example_id = item_id[:MAX_ID_CHARS]
        if content is not None and 1 <= len(content) <= MAX_EXAMPLE_CHARS:
            row = GoldenExample(
                example_id,
                guard_point,
                label,
                content,
                tuple(strings_tripwire(example_id, content)),
            )
            mode = "content"
        else:
            row = GoldenExample(
                example_id,
                guard_point,
                label,
                content_sha256 or "sha256:unknown",
                (HASH_ONLY_VIEW,),
            )
            mode = HASH_ONLY_VIEW
        try:
            info = await self._create(
                scope,
                decision,
                principal,
                ESCALATION_SET_PREFIX + item_id[:60],
                (row,),
                set_id=set_id,
            )
        except GoldenSetExistsError:  # a concurrent resolve of the same item made it first
            found = await store.get(scope.tenant_id, set_id)
            if found is None:
                raise
            return found, (HASH_ONLY_VIEW if _is_placeholder(found) else "content")
        return info, mode

    async def list_sets(
        self, decision: AuthzDecision, *, include: str | None = None
    ) -> list[GoldenSetInfo]:
        """The tenant's golden sets, oldest first (metadata only: never the examples).

        By default the sets the tenant uploaded. ``include="escalation"`` lists instead
        the one-example label sets that resolved escalations made, which the default list leaves
        out and which count toward the evidence gate's label counts. Any other value raises
        :class:`~guardrail_engine.escalation.model.InvalidQueryError` (HTTP 400)."""
        from guardrail_engine.admin.service import _scope_of
        from guardrail_engine.escalation.model import InvalidQueryError

        if include is not None and include != INCLUDE_ESCALATION:
            raise InvalidQueryError("include")
        scope = _scope_of(decision, LIST_GOLDEN)
        sets = await self._store.scoped(scope).list(scope.tenant_id)
        want = include == INCLUDE_ESCALATION
        return [i for i in sets if i.is_escalation_label == want]

    async def get_set(self, decision: AuthzDecision, set_id: str) -> GoldenSetInfo:
        """One set's metadata, with its quarantined rows by id and view. Raises
        :class:`GoldenSetNotFoundError` for an unknown id and for another tenant's."""
        from guardrail_engine.admin.service import _scope_of

        scope = _scope_of(decision, GET_GOLDEN)
        if not isinstance(set_id, str) or not GOLDEN_ID.fullmatch(set_id):
            raise GoldenSetNotFoundError()
        info = await self._store.scoped(scope).get(scope.tenant_id, set_id)
        if info is None:
            raise GoldenSetNotFoundError()
        return info


def _is_placeholder(info: GoldenSetInfo) -> bool:
    return any(HASH_ONLY_VIEW in views for _, views in info.quarantined)


__all__ = [
    "ESCALATION_SET_PREFIX",
    "INCLUDE_ESCALATION",
    "GoldenAuditEvent",
    "GoldenExample",
    "GoldenPage",
    "GoldenService",
    "GoldenSetExistsError",
    "GoldenSetInfo",
    "GoldenSetNotFoundError",
    "GoldenStore",
    "InMemoryGoldenStore",
    "ScopedGoldenStores",
    "TooManyGoldenSetsError",
    "examples_hash",
    "parse_upload",
]  # fmt: skip
