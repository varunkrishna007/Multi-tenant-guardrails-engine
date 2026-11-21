"""Resolving a tenant-chosen webhook host at send time. The address checks are in
``guardrail_engine.net_safety`` (pure); this is the one place that asks the resolver."""

from __future__ import annotations

import socket

from guardrail_engine.net_safety import (
    HostNotPublicError,
    HostUnresolvedError,
    host_literal,
    is_global_address,
)


def resolve_global(host: str, port: int, *, allow_non_global: bool = False) -> str:
    """The address to connect to for ``host``: resolved now, and every address it resolves to must
    be global (a name with one private answer is refused whole). Returns the first, as text.
    Raises :class:`HostNotPublicError` when an address is refused and
    :class:`HostUnresolvedError` when the name doesn't resolve.

    ``allow_non_global`` turns the refusal off and is for tests that talk to a ``127.0.0.1``
    server. It is a keyword of the code that sends, never read from a bundle, a tenant record or
    the environment."""
    literal = host_literal(host)
    if literal is not None:
        if not allow_non_global and not is_global_address(literal):
            raise HostNotPublicError()
        return str(literal)
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        raise HostUnresolvedError() from None
    addresses = [str(info[4][0]).split("%", 1)[0] for info in infos]
    if not addresses:
        raise HostUnresolvedError()
    if not allow_non_global and not all(is_global_address(a) for a in addresses):
        raise HostNotPublicError()
    return addresses[0]
