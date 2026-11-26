"""The guard service as a local process (M7-10): ``python -m guardrail_engine.service``.

    uv run --extra service python -m guardrail_engine.service \\
        --signing-key-file key.bin --tenant t_alpha --port 0

It builds the engine and serves the check listener (``service.adapters.fastapi_app``) with
uvicorn. **It is for the local simulation, not a deployment**:

* it listens on **loopback only** (``127.0.0.0/8``, ``::1`` or ``localhost``; any other ``--host``
  is refused before anything is bound) or on a **unix socket created owner-only (0600)**, removed
  when the service stops;
* it refuses any environment but ``test`` (a deployment wires its own stores, keyset, secrets and
  transport identity, none of which this runner reads);
* the model is the **fake** by default, answering after ``--fake-latency-s``; ``--fake-behaviour
  marked`` makes it decide by markers in the text (``decision.fake.MarkedFakeDecisionModel``).
  In fake mode a settings file that names dedicated projects is refused: building them would read
  the environment variables their ``key_env`` names, and nothing here may read a key without live
  mode. ``--model live`` builds the real Gemini adapter from ``GEMINI_API_KEY``; it needs the
  user's written approval (see ``docs/m7-10-guard-service.md``; the environment variable it is
  recorded in is a flag that you mean it, not the approval) and a required ``--max-live-calls``:
  the most requests this process will send to the provider **in its lifetime**. It is its own
  counter (apart from the daily request cap), never rolls, and is taken immediately before every
  send, retries and breaker probes included; past it nothing is sent and every check fails closed.
  A restart is a new run with a new count, so it needs its own approval;
* the signed contexts are the v1 HMAC scheme with the key in ``--signing-key-file``: the **raw
  bytes** of the file (no trimming), at least 32 and at most 4,096, in a regular file owned by the
  user running the service, mode owner-only, opened without following a symbolic link. Each
  ``--tenant`` is in an in-memory directory with a floor-only bundle published;
* it prints one line, ``{"listening": "<url>"}``, when it is ready, and stops on SIGINT or SIGTERM,
  draining the engine.

The settings file (``--settings``, JSON) is an ``EngineSettings`` mapping; ``environment`` is
forced to ``test``.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import os
import stat
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from guardrail_engine.decision import FakeDecisionModel, MarkedFakeDecisionModel
from guardrail_engine.decision.capped import CallCap, CappedDecisionModel
from guardrail_engine.engine.factory import build_engine
from guardrail_engine.engine.settings import EngineSettings
from guardrail_engine.floor_file import FLOOR_FILES, RELEASE_RECORDS
from guardrail_engine.guard import HmacContextVerifier, InMemoryTenantDirectory, TenantProfile
from guardrail_engine.policy import TenantAttributes
from guardrail_engine.service.adapters.fastapi_app import DEFAULT_MAX_BODY_BYTES, create_check_app
from guardrail_engine.service.adapters.uvicorn_server import (
    SocketPathError,
    open_listener,
    serve_app,
)

LIVE_KEY = "GUARDRAILS_LIVE_SERVICE"
LIVE_TOKEN = "m7-10-live-service-approved"
MIN_KEY_BYTES = 32
MAX_KEY_BYTES = 4096
DOC = "docs/m7-10-guard-service.md"
DEFAULT_TENANT = "t_local"


class Refused(SystemExit):
    """The runner won't start; the message says why (never a secret)."""

    def __init__(self, message: str) -> None:
        super().__init__(f"refused: {message}")


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="python -m guardrail_engine.service", description=__doc__)
    p.add_argument("--settings", type=Path, help="EngineSettings mapping, JSON (environment: test)")
    p.add_argument("--signing-key-file", type=Path, required=True)
    p.add_argument("--tenant", action="append", dest="tenants", help="a tenant id (repeatable)")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=0, help="0 picks a free port")
    p.add_argument("--uds", type=Path, help="serve on this unix socket instead of host and port")
    p.add_argument("--model", choices=("fake", "live"), default="fake")
    p.add_argument("--fake-latency-s", type=float, default=0.0)
    p.add_argument(
        "--fake-behaviour",
        choices=("allow", "marked"),
        default="allow",
        help="marked: decide by [mix:...] markers in the text",
    )
    p.add_argument(
        "--max-live-calls",
        type=int,
        default=None,
        help="required with --model live: the most requests the service will send (no default)",
    )
    p.add_argument("--max-body-bytes", type=int, default=DEFAULT_MAX_BODY_BYTES)
    return p.parse_args(argv)


def check_host(host: str) -> None:
    """Refuse a listening address that isn't loopback, before anything is bound."""
    if host == "localhost":
        return
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = False
    if not loopback:
        raise Refused("the runner listens on loopback only (127.0.0.0/8, ::1 or localhost)")


def load_settings(path: Path | None, *, live: bool = False) -> EngineSettings:
    data: dict[str, Any] = json.loads(path.read_text()) if path else {}
    if not isinstance(data, dict):
        raise Refused("the settings file must hold a JSON object")
    if data.get("environment", "test") != "test":
        raise Refused(
            "this runner is for the local simulation and serves the test environment only; "
            "a deployment wires its own stores, keyset and secrets"
        )
    if not live and (data.get("projects") or {}).get("dedicated"):
        raise Refused(
            "dedicated projects are not served with the fake model: building them would read the "
            "environment variables their key_env names"
        )
    data["environment"] = "test"
    catalog = data.setdefault("catalog", {})
    catalog.setdefault("floor_files", FLOOR_FILES)
    catalog.setdefault("release_records", RELEASE_RECORDS)
    data.setdefault("signed_context", {}).setdefault("allow_v1_hmac", True)
    return EngineSettings.from_mapping(data)


def read_key(path: Path) -> bytes:
    """The signing key: the file's raw bytes. The file must be a regular file owned by the user
    running the service, owner-only (no group or other permission bit), at most 4,096 bytes, and is
    opened without following a symbolic link. Nothing about the key is ever printed."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError:
        raise Refused(
            "the signing key file can't be opened (missing, or a symbolic link)"
        ) from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise Refused("the signing key file must be a regular file")
        if info.st_uid != os.geteuid():
            raise Refused("the signing key file must be owned by the user running the service")
        if info.st_mode & 0o077:
            raise Refused("the signing key file must be owner-only (mode 0600)")
        if info.st_size > MAX_KEY_BYTES:
            raise Refused(f"the signing key file must be at most {MAX_KEY_BYTES} bytes")
        key = os.read(fd, MAX_KEY_BYTES + 1)
    finally:
        os.close(fd)
    if len(key) > MAX_KEY_BYTES:
        raise Refused(f"the signing key file must be at most {MAX_KEY_BYTES} bytes")
    if len(key) < MIN_KEY_BYTES:
        raise Refused(f"the signing key must be at least {MIN_KEY_BYTES} bytes")
    return key


def cap_live_calls(engine: Any, limit: int) -> CallCap:
    """Cap the requests this process sends to the provider, over every gateway (the shared pool's
    and each dedicated project's), with one counter."""
    cap = CallCap(limit)
    for gateway in engine.guard.gateways.values():
        gateway.wrap_model(lambda model: CappedDecisionModel(model, cap))
    return cap


def profile(tenant_id: str) -> TenantProfile:
    return TenantProfile.build(
        TenantAttributes(tenant_id=tenant_id, tier="standard"),
        "insurance",
        slug=tenant_id.removeprefix("t_"),
    )


def check_live_approval(args: argparse.Namespace, environ: dict[str, str]) -> None:
    """Live mode needs the user's written approval, recorded in the environment (the variable's
    value is a flag that you mean it; it is not printed), and a call cap."""
    if args.model != "live":
        if args.max_live_calls is not None:
            raise Refused("--max-live-calls belongs to --model live")
        return
    if environ.get(LIVE_KEY) != LIVE_TOKEN:
        raise Refused(
            f"--model live needs the user's written approval, recorded in the environment as "
            f"{LIVE_KEY}; see {DOC}"
        )
    if args.max_live_calls is None or args.max_live_calls < 1:
        raise Refused("--model live needs --max-live-calls, a whole number of at least 1")


async def serve(args: argparse.Namespace, environ: dict[str, str] | None = None) -> None:
    check_host(args.host)
    check_live_approval(args, environ if environ is not None else dict(os.environ))
    settings = load_settings(args.settings, live=args.model == "live")
    key = read_key(args.signing_key_file)
    # Bound first: an address or a socket path that can't be used is refused before the engine
    # is built, as one line.
    try:
        listener = open_listener(args.host, args.port, args.uds)
    except SocketPathError as exc:
        raise Refused(str(exc)) from None
    except OSError as exc:  # an address in use, a directory that doesn't exist
        raise Refused(f"can't listen: {exc.strerror or type(exc).__name__}") from None
    try:
        await run_engine(args, settings, key, listener)
    finally:
        listener.close()


async def run_engine(
    args: argparse.Namespace, settings: EngineSettings, key: bytes, listener: Any
) -> None:
    tenants = args.tenants or [DEFAULT_TENANT]
    model: FakeDecisionModel | None = None
    if args.model == "fake":
        fake_class = (
            MarkedFakeDecisionModel if args.fake_behaviour == "marked" else FakeDecisionModel
        )
        model = fake_class(latency_s=args.fake_latency_s)
    engine = await build_engine(
        settings,
        verifier=HmacContextVerifier(key),
        tenants=InMemoryTenantDirectory([profile(t) for t in tenants]),
        **({"model": model} if model is not None else {}),
    )
    try:
        for tenant in tenants:
            await engine.bootstrap_publish(
                {
                    "schema_version": 1,
                    "tenant_id": tenant,
                    "version": 1,
                    "extends": ["platform/floor@1"],
                }
            )
        if args.model == "live":
            cap_live_calls(engine, args.max_live_calls)
        app = create_check_app(engine, max_body_bytes=args.max_body_bytes)

        def started(url: str) -> None:
            print(json.dumps({"listening": url}), flush=True)

        await serve_app(app, listener, on_started=started)
    finally:
        await engine.shutdown()


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    asyncio.run(serve(args))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
