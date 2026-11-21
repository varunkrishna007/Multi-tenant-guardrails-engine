"""Shared helpers for the engine composition root tests (M1-11).

The engine is built with the real floor file (``floor/rules.json``), as in production. No
test here needs an API key, a database or the network: the Gemini adapter is pointed at an
``httpx.MockTransport`` or a local server on 127.0.0.1, and keys are sentinels set with
``monkeypatch``.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import httpx

from guardrail_engine.engine import EngineSettings
from guardrail_engine.floor_file import load_floor_file
from guardrail_engine.guard import (
    CheckContext,
    HmacContextVerifier,
    InMemoryTenantDirectory,
    TenantProfile,
)
from guardrail_engine.policy import InMemoryCatalog, TenantAttributes

ROOT = Path(__file__).resolve().parents[2]
FLOOR_FILE = ROOT / "floor" / "rules.json"
SIGNING_KEY = b"m1-11 test signing key, 32+ bytes long"
TENANT = "t_dogfood"
LOCAL_URL = "http://127.0.0.1:9/v1beta"
"""A loopback base URL: allowed over plain http. Never contacted with a MockTransport."""


def settings(environment: str = "test", **sections: Any) -> EngineSettings:
    """Engine settings with the real floor file by absolute path, ``environment`` (default
    ``test``, so ``bootstrap_publish`` is allowed), and any sections given as mappings
    merged over the defaults."""
    data: dict[str, Any] = {
        "catalog": {"floor_files": [str(FLOOR_FILE)]},
        "environment": environment,
        # These tests use the v1 HMAC verifier; a production engine refuses one unless allowed.
        "signed_context": {"allow_v1_hmac": True},
    }
    for name, value in sections.items():
        data[name] = {**data.get(name, {}), **value}
    return EngineSettings.from_mapping(data)


def adapter_settings(**sections: Any) -> EngineSettings:
    """Settings that let the engine build the Gemini adapter (paid tier declared, local URL)."""
    gemini = {"paid_tier": True, "base_url": LOCAL_URL, **sections.pop("gemini", {})}
    return settings(gemini=gemini, **sections)


def real_catalog() -> InMemoryCatalog:
    """A catalog holding the real floor, for stores built by a test."""
    return InMemoryCatalog(floors=[load_floor_file(FLOOR_FILE)])


def profile(tenant_id: str = TENANT, *, tier: str = "standard") -> TenantProfile:
    """A directory entry. The slug and id must pass the B3 identity checks (main's
    ``TENANT_SLUG_PATTERN`` and ``TENANT_ID_PATTERN``); the slug is the id without ``t_``."""
    return TenantProfile.build(
        TenantAttributes(tenant_id=tenant_id, tier=tier),
        "insurance",
        slug=tenant_id.removeprefix("t_"),
    )


class FixtureDirectory(InMemoryTenantDirectory):
    """The in-memory directory, with the explicit opt-out of the cross-tenant identifier scan
    that a production or staging engine needs: the engine tests that build one aren't
    about the scan. A plain ``InMemoryTenantDirectory`` there is refused at startup."""

    def other_tenant_identifiers(self):
        from guardrail_engine.deterministic import NoOtherTenantIdentifiers

        return NoOtherTenantIdentifiers()


def directory(*profiles: TenantProfile) -> InMemoryTenantDirectory:
    return FixtureDirectory(profiles or [profile()])


def verifier() -> HmacContextVerifier:
    return HmacContextVerifier(SIGNING_KEY)


def bundle(tenant_id: str = TENANT, version: int = 1) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "tenant_id": tenant_id,
        "version": version,
        "extends": ["platform/floor@1"],
    }


def ctx(v: HmacContextVerifier, tenant_id: str = TENANT) -> CheckContext:
    return CheckContext(signed_context=v.issue(tenant_id))


def answer_everything(request: httpx.Request, *, noul: float = 0.01) -> httpx.Response:
    """A Decisions API stand-in: answers every question asked, ``noul`` for yes/no ones."""
    body = json.loads(request.content)
    answers = {}
    for key, question in body["questions"].items():
        if question["type"] == "noul":
            answers[key] = {"type": "noul", "noul": noul, "confidence": 0.9}
        elif question["type"] == "choice":
            option = next(iter(question["criteria"]))
            answers[key] = {"type": "choice", "choice": option, "confidence": 0.9}
        else:
            answers[key] = {"type": "score", "score": 0, "confidence": 0.9}
    return httpx.Response(200, json={"answers": answers, "usage": {"total_input_tokens": 100}})


class LocalDecisionsServer:
    """A keep-alive HTTP/1.1 server on 127.0.0.1 that answers every question it is asked.
    Real sockets, so httpcore reports whether each call reused a connection."""

    def __init__(self) -> None:
        self.connections = 0
        self._writers: set[asyncio.StreamWriter] = set()

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.base_url = f"http://127.0.0.1:{self._server.sockets[0].getsockname()[1]}/v1beta"

    async def stop(self) -> None:
        self._server.close()
        for writer in list(self._writers):
            writer.close()
        await self._server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.connections += 1
        self._writers.add(writer)
        try:
            while True:
                head = await reader.readuntil(b"\r\n\r\n")
                length = next(
                    int(line.split(b":", 1)[1])
                    for line in head.split(b"\r\n")
                    if line.lower().startswith(b"content-length:")
                )
                body = await reader.readexactly(length)
                request = httpx.Request("POST", "http://x/", content=body)
                payload = answer_everything(request).content
                writer.write(
                    b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n"
                    b"content-length: %d\r\n\r\n" % len(payload) + payload
                )
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            self._writers.discard(writer)
            writer.close()
