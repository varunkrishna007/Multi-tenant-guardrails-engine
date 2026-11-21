"""The escalation queue (M4-05): human queue and tenant webhook, resolutions that become golden
labels, and the class D deletion job. See ``docs/m4-05-escalation-queue.md``.

The Postgres adapter (``escalation/adapters/postgres.py``) and the webhook sink
(``escalation/adapters/webhook.py``) are imported by the composition root only, so importing this
package loads no database driver or HTTP code.
"""

from guardrail_engine.escalation.model import (
    EscalationItem,
    EscalationRequest,
    ItemFilter,
    ItemPage,
    Resolution,
    RuleRef,
)
from guardrail_engine.escalation.retention import (
    CatalogClassDResolver,
    ClassDJob,
    ClassDReport,
    ClassDTerm,
)
from guardrail_engine.escalation.router import EscalationRouter, request_from_check
from guardrail_engine.escalation.service import EscalationService
from guardrail_engine.escalation.store import (
    ClassDStore,
    EscalationStore,
    InMemoryEscalationStore,
    ScopedEscalationStores,
)

__all__ = [
    "CatalogClassDResolver",
    "ClassDJob",
    "ClassDReport",
    "ClassDStore",
    "ClassDTerm",
    "EscalationItem",
    "EscalationRequest",
    "EscalationRouter",
    "EscalationService",
    "EscalationStore",
    "InMemoryEscalationStore",
    "ItemFilter",
    "ItemPage",
    "Resolution",
    "RuleRef",
    "ScopedEscalationStores",
    "request_from_check",
]
