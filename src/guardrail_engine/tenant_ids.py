"""The one tenant id rule (B3).

A tenant id is ``t_`` then 1-32 lowercase letters or digits. Ids are platform-generated
(:func:`new_tenant_id`), never chosen by a tenant. The same pattern is enforced wherever an
id is created or accepted: the bundle schema's ``tenant_id``, the policy store's keys, the
signed context, the tenant directory and the ``TENANT`` header. So no tenant can exist that
can't authenticate.
"""

from __future__ import annotations

import re
import secrets

TENANT_ID_PATTERN = re.compile(r"t_[0-9a-z]{1,32}")
"""Use with ``fullmatch``."""

_BASE36 = "0123456789abcdefghijklmnopqrstuvwxyz"
GENERATED_ID_CHARS = 10


def is_valid_tenant_id(value: object) -> bool:
    return isinstance(value, str) and TENANT_ID_PATTERN.fullmatch(value) is not None


def new_tenant_id() -> str:
    """A fresh id: ``t_`` plus 10 random base-36 characters. Random, not sequential, so an id
    carries no meaning and doesn't reveal how many tenants exist."""
    return "t_" + "".join(secrets.choice(_BASE36) for _ in range(GENERATED_ID_CHARS))
