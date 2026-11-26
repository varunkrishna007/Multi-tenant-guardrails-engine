"""The escalation webhook sink (M4-05): a signed POST of an escalation notice, for the outbox
dispatcher (``OutboxDispatcher(escalations=...)``).

It reuses the M4-04 machinery: the same HMAC-SHA256 signature over ``"<timestamp>.<body>"``
(``X-Guardrail-Signature: v1=<hex>``), the same headers, and the outbox event's idempotency key,
which is the same on every retry (``X-Guardrail-Idempotency-Key``: drop a repeat). Retries,
backoff and the dead-letter state are the dispatcher's.

**Request body**::

    {"id": "<idempotency key>", "type": "escalation", "sent_at": <epoch s>,
     "escalation": {"id": "esc_...", "tenant_id": "t_...", "guard_point": "output",
                    "reason": "policy", "created_at": <epoch s>, "bundle_version": 7,
                    "content_sha256": "sha256:...", "content_available": false,
                    "rules": [{"key": "d__x", "action": "escalate", "mode": "enforce"}],
                    "resolve": {"method": "POST", "path": "/v1/tenants/t_.../guardrails/
                                escalations/esc_.../resolve"}}}

**What it never carries.** No content (see ``EscalationNotice`` in ``delivery/events.py``
for why) and no probability: floor rules and floor-derived tenant rules appear by key and action
only, as in a production verdict. ``content_sha256`` is the hash of the pre-redaction content.

**Where the url and the secret come from.** The url is the one in the tenant's bundle when the
item was routed, carried in the notice and checked again here: https, no credentials,
and a host that is on the public internet. The host is resolved when the notice is sent, every
address must be global (private, loopback, link-local, CGNAT, multicast, unspecified, ULA and
IPv4-mapped forms are refused with the code ``host_not_public``, and nothing is connected to),
and the connection goes to the address that was checked, with the hostname kept for the TLS
server name, the certificate check and the Host header, so a DNS answer that changes between
the check and the connect can't redirect it. The signing secret is **per tenant** and never
stored in the outbox or the bundle: ``secrets`` returns it for a tenant id (from the platform's
secret store), and a tenant with no secret fails the delivery with the code ``no_secret``
(dead-lettered after the retry window, and raised as ``events_dead_lettered``). A url or secret is
never logged, in an exception message or in a repr.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Protocol

from guardrail_engine.delivery.adapters.webhook import (
    check_secret,
    post_signed_pinned,
    validate_tenant_webhook_url,
)
from guardrail_engine.delivery.dispatcher import DeliveryError
from guardrail_engine.delivery.events import EscalationNotice


class WebhookSecrets(Protocol):
    def secret_for(self, tenant_id: str) -> str | bytes | None:
        """The tenant's webhook signing secret (at least 16 bytes), or None if it has none."""
        ...


class StaticWebhookSecrets:
    """A fixed map of tenant id to secret, for tests and single-box setups."""

    def __init__(self, secrets: dict[str, str | bytes]) -> None:
        self._secrets = dict(secrets)

    def secret_for(self, tenant_id: str) -> str | bytes | None:
        return self._secrets.get(tenant_id)

    def __repr__(self) -> str:
        return "StaticWebhookSecrets(<redacted>)"


def resolve_path(tenant_id: str, item_id: str) -> str:
    return f"/v1/tenants/{tenant_id}/guardrails/escalations/{item_id}/resolve"


class EscalationWebhookSink:
    def __init__(
        self,
        secrets: WebhookSecrets,
        *,
        timeout_s: float = 5.0,
        clock: Callable[[], float] = time.time,
        allow_non_global_hosts_for_tests: bool = False,
    ) -> None:
        """``allow_non_global_hosts_for_tests`` lets a test post to a ``127.0.0.1`` server (and
        over plain http). It is off by default, is a constructor argument only (nothing a tenant
        configures, and no environment variable, can turn it on), and a deployment must never
        set it."""
        if timeout_s <= 0:
            raise ValueError("timeout_s must be positive")
        self._secrets = secrets
        self._timeout_s = timeout_s
        self._clock = clock
        self._allow_non_global = allow_non_global_hosts_for_tests

    def __repr__(self) -> str:
        return "EscalationWebhookSink(<redacted>)"

    def deliver(self, notice: EscalationNotice, idempotency_key: str) -> None:
        try:
            validate_tenant_webhook_url(notice.url, allow_non_global=self._allow_non_global)
        except ValueError:
            raise DeliveryError("bad_url") from None
        try:
            secret = self._secrets.secret_for(notice.tenant_id)
            key = None if secret is None else check_secret(secret)
        except Exception:
            raise DeliveryError("no_secret") from None
        if key is None:
            raise DeliveryError("no_secret")
        sent_at = self._clock()
        document = {
            "id": idempotency_key,
            "type": "escalation",
            "sent_at": int(sent_at),
            "escalation": {
                "id": notice.item_id,
                "tenant_id": notice.tenant_id,
                "guard_point": notice.guard_point,
                "reason": notice.reason,
                "created_at": int(notice.created_at),
                "bundle_version": notice.bundle_version,
                "content_sha256": notice.content_sha256,
                "content_available": notice.content_available,
                "rules": [{"key": k, "action": a, "mode": m} for k, a, m in notice.rules],
                "candidate_rules": list(notice.candidate_rules),
                "resolve": {
                    "method": "POST",
                    "path": resolve_path(notice.tenant_id, notice.item_id),
                },
            },
        }
        post_signed_pinned(
            notice.url,
            key,
            idempotency_key,
            document,
            sent_at=sent_at,
            timeout_s=self._timeout_s,
            allow_non_global=self._allow_non_global,
        )
