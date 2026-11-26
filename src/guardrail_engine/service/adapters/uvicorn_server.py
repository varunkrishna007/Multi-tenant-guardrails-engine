"""Serves an ASGI app with uvicorn for the local runner (M7-10). The only module that imports
uvicorn, so a runtime that only checks never loads a web server.

**A unix socket is created owner-only.** uvicorn's own binding makes a new socket world-writable
(0666), so this module binds the socket itself, under ``umask(0o077)``, sets 0600, and hands the
listening socket to uvicorn, which then never changes its mode. The socket is removed when the
server stops, but only if the file is still the one this process created (its device and inode).
A path that already holds a socket is replaced only if it is stale (a connection to it is
refused); one that answers is in use and is refused, and so is anything else there, a symbolic
link included.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import signal
import socket
import stat
import threading
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import uvicorn


class SocketPathError(RuntimeError):
    """The unix socket's path can't be used (the message names the kind of problem only)."""


class _Server(uvicorn.Server):
    @contextlib.contextmanager
    def capture_signals(self) -> Iterator[None]:
        """uvicorn re-raises a signal it caught once it has stopped, which would end the process
        before the engine has drained. Stop on SIGINT or SIGTERM and return."""
        if threading.current_thread() is not threading.main_thread():
            yield
            return
        handled = (signal.SIGINT, signal.SIGTERM)
        original = {sig: signal.signal(sig, self.handle_exit) for sig in handled}
        try:
            yield
        finally:
            for sig, handler in original.items():
                signal.signal(sig, handler)


def _answers(path: Path) -> bool:
    """Whether something accepts a connection on the socket at ``path``. Only a refused
    connection (or a socket that has gone) means it is stale; anything else, a timeout included,
    is treated as in use."""
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    probe.settimeout(1.0)
    try:
        probe.connect(str(path))
    except (ConnectionRefusedError, FileNotFoundError):
        return False
    except OSError:
        return True
    finally:
        probe.close()
    return True


def check_socket_path(path: Path) -> None:
    """Raise :class:`SocketPathError` if ``path`` can't be used: it holds something that isn't a
    socket, or a socket something is listening on. A stale socket, or nothing, is fine. Cheap, so
    the runner can refuse before it builds anything."""
    try:
        existing = os.lstat(path)
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(existing.st_mode):
        raise SocketPathError("the socket path already holds something that is not a socket")
    if _answers(path):
        raise SocketPathError("the socket path is in use: something is listening on it")


def bind_private_socket(path: Path) -> tuple[socket.socket, tuple[int, int]]:
    """A listening unix socket at ``path``, mode 0600 from the moment it exists, and its
    ``(device, inode)``. Raises :class:`SocketPathError` for a path that holds something that
    isn't a socket."""
    check_socket_path(path)
    with contextlib.suppress(FileNotFoundError):
        os.unlink(path)  # a stale socket from an earlier run: nothing answers
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    previous = os.umask(0o077)
    try:
        sock.bind(str(path))
    except OSError:
        sock.close()
        raise
    finally:
        os.umask(previous)
    os.chmod(path, 0o600)
    sock.listen(2048)
    sock.setblocking(False)
    made = os.stat(path)
    return sock, (made.st_dev, made.st_ino)


def remove_socket_if_ours(path: Path, identity: tuple[int, int]) -> None:
    """Unlink ``path`` if it is still the socket created here."""
    try:
        now = os.lstat(path)
    except FileNotFoundError:
        return
    if stat.S_ISSOCK(now.st_mode) and (now.st_dev, now.st_ino) == identity:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(path)


class Listener:
    """A bound, listening socket, and what to clean up when it is done with."""

    def __init__(
        self,
        sock: socket.socket,
        url: str,
        uds: Path | None = None,
        identity: tuple[int, int] | None = None,
    ) -> None:
        self.sock = sock
        self.url = url
        self._uds = uds
        self._identity = identity

    def close(self) -> None:
        """Close the socket and remove a unix socket this process made."""
        self.sock.close()
        if self._uds is not None and self._identity is not None:
            remove_socket_if_ours(self._uds, self._identity)


def open_listener(host: str, port: int, uds: Path | None) -> Listener:
    """Bind the listening socket now, so that a path or a port that can't be used is refused
    before anything else is built. Raises :class:`SocketPathError` for a bad socket path and
    ``OSError`` for an address that can't be bound (in use, not permitted)."""
    if uds is not None:
        sock, identity = bind_private_socket(uds)
        return Listener(sock, f"unix://{uds}", uds, identity)
    family, _, _, _, address = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)[0]
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(address)
        sock.listen(2048)
        sock.setblocking(False)
    except OSError:
        sock.close()
        raise
    bound = sock.getsockname()
    shown = f"[{bound[0]}]" if family == socket.AF_INET6 else bound[0]
    return Listener(sock, f"http://{shown}:{bound[1]}")


async def serve_app(app: Any, listener: Listener, *, on_started: Callable[[str], None]) -> None:
    """Serve ``app`` on ``listener`` until SIGINT or SIGTERM. ``on_started`` gets the URL once the
    server runs. The caller closes the listener."""
    config = uvicorn.Config(
        app,
        log_level="warning",
        access_log=False,
        server_header=False,
        date_header=False,
    )
    server = _Server(config)
    task = asyncio.ensure_future(server.serve(sockets=[listener.sock]))
    while not server.started and not task.done():
        await asyncio.sleep(0.02)
    if server.started:
        on_started(listener.url)
    await task
