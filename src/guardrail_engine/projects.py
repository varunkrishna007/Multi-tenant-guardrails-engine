"""Gemini projects and key pools (M5-06): labels, the pool configuration and the assignment of a
regulated tenant to a dedicated project.

**A project is a label.** The label (``acme-reg``, ``shared-1``) is the only thing that names a
project in the directory, in usage rows and in metrics. A project's *key* is never in a setting,
a record, a log or a response: the setting holds the **name of the environment variable** the key
is read from when the engine is built (``key_env``), exactly as the single key is read from
``GEMINI_API_KEY``. A label and an environment-variable name are not secrets; the value of the
variable is, and nothing here ever holds it.

**Pools.** ``shared`` is the pool every standard tenant uses: the engine's default project
(label ``default``, the key in ``GEMINI_API_KEY``). ``dedicated`` projects each serve **one**
tenant, so that tenant's per-minute token quota, daily request count and monthly spend are its
own and its usage and billing are attributable (the design's "key pools" row). A regulated
tenant is assigned a free dedicated project when it is provisioned or raised to a regulated tier;
:class:`DedicatedProjects` decides which, and what happens when there is none.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Protocol

logger = logging.getLogger(__name__)

DEFAULT_PROJECT = "default"
"""The shared pool's project: the engine's own gateway, ``GEMINI_API_KEY`` and ``token_rate``.
A tenant with no assignment uses it, and usage rows with no project are attributed to it."""
PROJECT_LABEL_PATTERN = re.compile(r"[a-z0-9][a-z0-9-]{0,39}")
"""Use with ``fullmatch``. Lower case, digits and hyphens: a label that is also safe in a log
line, a metrics key and a header."""
KEY_ENV_PATTERN = re.compile(r"[A-Z][A-Z0-9_]{1,63}")
"""Use with ``fullmatch``: an environment variable name, not a value. A key ("AIza...") has
lower-case letters and punctuation, so it can never pass for a name."""
POOLS = ("shared", "dedicated")


def is_valid_project_label(value: object) -> bool:
    return isinstance(value, str) and PROJECT_LABEL_PATTERN.fullmatch(value) is not None


def is_valid_key_env(value: object) -> bool:
    return isinstance(value, str) and KEY_ENV_PATTERN.fullmatch(value) is not None


class NoDedicatedProject(Exception):
    """A regulated tenant needs a dedicated Gemini project and none is free, in an environment
    that does not allow the shared fallback (``production`` and ``staging``). The message is an
    operator's: it names the setting to change and never a tenant's content or a key."""

    code = "no_dedicated_project"


class ProjectAssignments(Protocol):
    """What the tenant directory's write path asks of the pool configuration."""

    def knows(self, project: str) -> bool:
        """Whether ``project`` is a configured dedicated project."""
        ...

    def choose(self, taken: Iterable[str], *, tenant_id: str) -> str | None:
        """A dedicated project not in ``taken``, for a regulated tenant. None means "use the
        shared pool" and is returned only where the environment allows the fallback (``test``:
        with a warning). Raises :class:`NoDedicatedProject` where it doesn't."""
        ...


@dataclass(frozen=True, slots=True)
class DedicatedProjects:
    """The configured dedicated projects, in the order they are handed out, and the
    environment's rule for running out of them."""

    labels: tuple[str, ...] = ()
    environment: str = "production"

    def __post_init__(self) -> None:
        bad = [label for label in self.labels if not is_valid_project_label(label)]
        if bad or len(set(self.labels)) != len(self.labels) or DEFAULT_PROJECT in self.labels:
            raise ValueError(
                "dedicated project labels must be distinct, match "
                f"{PROJECT_LABEL_PATTERN.pattern} and not be {DEFAULT_PROJECT!r}"
            )

    @classmethod
    def of(cls, labels: Sequence[str], *, environment: str) -> DedicatedProjects:
        return cls(tuple(labels), environment)

    def knows(self, project: str) -> bool:
        return project in self.labels

    def choose(self, taken: Iterable[str], *, tenant_id: str) -> str | None:
        used = set(taken)
        for label in self.labels:
            if label not in used:
                return label
        if self.environment == "test":
            logger.warning(
                "no free dedicated Gemini project for regulated tenant %s: using the shared "
                "pool (environment is test; production and staging refuse)",
                tenant_id,
            )
            return None
        configured = "none is configured" if not self.labels else "all are in use"
        raise NoDedicatedProject(
            f"no dedicated Gemini project is free for a regulated tenant ({configured}): add a "
            f"dedicated project under the 'projects' setting before provisioning or raising "
            f"it ({self.environment} does not fall back to the shared pool)"
        )
