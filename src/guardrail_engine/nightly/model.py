"""What the nightly red-team (M5-05) records, per tenant version.

Each night the job runs the M2-08 corpus once for every distinct **configuration** the platform
serves (the floor version and the packs an active bundle extends) and records the outcome for
every tenant version that has it. A result holds counts and rule keys only: recall cells, a
status, the regressions it found, the usage it cost. It never holds a corpus row, a payload or
any tenant content (the run uses synthetic tenants; no tenant's data is read).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final

MODES: Final = ("fake", "live")
STATUSES: Final = ("pass", "regression", "refused", "stopped")
"""``pass``: no regression and every model-independent defence held. ``regression``: a floor
rule's block_at recall fell more than one cell below the previous night's, or below the release
baseline's, or a defence failed. ``refused``: the run was not made or can't be judged (a gate, a
bad corpus, an incomplete run). ``stopped``: it began and was stopped (a provider refusal, auth,
the failure rate, a ceiling)."""
MAX_REGRESSIONS: Final = 50


@dataclass(frozen=True, slots=True)
class NightlyResult:
    tenant_id: str
    bundle_version: int
    config_key: str
    """``platform/floor@2+domain/finance@1+...`` (``reg-acme|`` in front for a dedicated
    project): what decides the result (a tenant's own rules and overrides are not part of it)."""
    run_id: str
    run_at: datetime
    mode: str
    floor_version: int
    packs: tuple[str, ...]
    corpus_sha256: str
    draws: int
    rows: int
    status: str
    regressions: tuple[dict[str, Any], ...]
    block_recall: dict[str, Any]
    """Per floor rule: ``{"hits": n, "cells": n}`` at ``block_at`` (what the gate compares)."""
    false_act: dict[str, Any]
    structure_violations: int
    provider_calls: int
    input_tokens: int
    nonce_seed: str = ""
    """The nonce seed the run's inputs were drawn with: a night is compared with the
    previous only if it used the same seed, corpus and draws."""
    project: str = ""
    """The Gemini project the check calls went out on (M5-06): a regulated tenant's dedicated
    project label, or ``""`` for the shared pool. Its quota, spend and key are its own."""
    note: str = ""
    """A fixed phrase for ``refused`` and ``stopped`` (never a row, a payload or provider text)."""


@dataclass(frozen=True, slots=True)
class QuarantineEvent:
    """One step of a configuration's quarantine, an append-only class A record: a
    provider refusal puts a configuration in quarantine (actor ``nightly``), and only a platform
    operator takes it out. A configuration is quarantined while its latest event is a
    ``quarantine``. Counts and keys only: never a row, a payload or provider text."""

    config_key: str
    mode: str
    project: str
    action: str
    """``quarantine`` or ``clear``."""
    at: datetime
    actor: str
    operator: bool
    reason: str
    """A fixed phrase for a quarantine; the operator's reason (1 to 200 characters) for a clear."""
    run_id: str = ""
    row_id: str = ""
    """The corpus row the provider refused: an id, never content. A hold on the row
    itself has the key :func:`row_key` and holds it across every configuration and project."""


ROW_KEY_PREFIX = "row:"


def row_key(row_id: str) -> str:
    """The quarantine key that holds one corpus row: no configuration key starts with
    ``row:`` (a project label has no colon)."""
    return f"{ROW_KEY_PREFIX}{row_id}"


CORPUS_HOLD_KEY = row_key("*")
"""The quarantine key that holds the **whole** live corpus, put when a provider refusal
arrives without a usable row id (so which row to leave out is unknown). ``*`` is no corpus id, so
the key never collides with a row's. An operator clears it like any other hold."""


def config_key(floor_ref: str, pack_refs: tuple[str, ...], project: str = "") -> str:
    key = "+".join([floor_ref, *sorted(pack_refs)])
    return f"{project}|{key}" if project else key
