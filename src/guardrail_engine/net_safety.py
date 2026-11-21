"""Which network addresses a tenant-chosen webhook may reach.

A tenant names its escalation webhook in its bundle, and the platform's dispatcher is what sends
to it, from inside the platform's network. TLS verification stops most server-side request
forgery, but not an internal service that holds a publicly trusted certificate, so the host
must be a **global** address:

* :func:`is_global_address` is the one test. Private (RFC 1918 and ULA ``fc00::/7``), loopback,
  link-local (including the cloud metadata address), CGNAT (``100.64.0.0/10``), multicast,
  unspecified, reserved and documentation ranges are refused, and so are the IPv6 forms that
  carry an IPv4 address (IPv4-mapped ``::ffff:a.b.c.d``, IPv4-compatible, NAT64 ``64:ff9b::/96``
  and 6to4 ``2002::/16``), judged by the IPv4 address inside them.
* :func:`literal_host_problem` is the check that needs no network, for the moment a url is
  configured: an IP literal must be global, and the names that only mean "this machine or this
  network" (``localhost``, ``*.localhost``, ``*.local``, ``*.internal``, ``*.lan``, a name without
  a dot) are refused. The bundle compiler runs it.
* ``resolve_global`` (``delivery/adapters/resolve.py``, where the socket module is allowed) is the
  check at send time: it resolves the name and refuses unless every address is global, and
  returns the address that was checked, so the caller connects to **that** address and a second
  lookup can't hand it another (DNS rebinding).

This module is pure (no socket, no url library), so the policy compiler can use it.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Final

__all__ = [
    "HostNotPublicError",
    "HostUnresolvedError",
    "host_literal",
    "is_global_address",
    "literal_host_problem",
    "url_host",
]

_CGNAT: Final = ipaddress.ip_network("100.64.0.0/10")
_NAT64: Final = ipaddress.ip_network("64:ff9b::/96")
_V4_COMPATIBLE: Final = ipaddress.ip_network("::/96")
_SIX_TO_FOUR: Final = ipaddress.ip_network("2002::/16")
_LOCAL_SUFFIXES: Final = (
    ".localhost", ".local", ".internal", ".lan", ".home", ".corp", ".intranet",
)  # fmt: skip


class HostNotPublicError(Exception):
    """The host is, or resolves to, an address a tenant's webhook may not reach. Carries no host
    or address, so nothing the tenant chose reaches a log line."""


class HostUnresolvedError(Exception):
    """The name did not resolve (a transient or a permanent DNS failure): worth a retry."""


def _embedded_v4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip in _NAT64 or ip in _V4_COMPATIBLE:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    if ip in _SIX_TO_FOUR:
        return ipaddress.IPv4Address((int(ip) >> 80) & 0xFFFFFFFF)
    return None


def is_global_address(address: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True only for an address on the public internet. Anything that doesn't parse is not."""
    try:
        ip = ipaddress.ip_address(address) if isinstance(address, str) else address
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        inner = _embedded_v4(ip)
        if inner is not None:
            return is_global_address(inner)
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
        or not ip.is_global
    ):
        return False
    return not (isinstance(ip, ipaddress.IPv4Address) and ip in _CGNAT)


def host_literal(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    bare = host.strip("[]").split("%", 1)[0]
    try:
        return ipaddress.ip_address(bare)
    except ValueError:
        return None


def literal_host_problem(host: str) -> str | None:
    """Why ``host`` can't be a tenant's webhook, judged without any network call, or None.
    A name that passes may still resolve to a private address; :func:`resolve_global` checks that
    at send time."""
    name = host.strip().rstrip(".").lower()
    if not name:
        return "the url has no host"
    literal = host_literal(name)
    if literal is not None:
        if is_global_address(literal):
            return None
        return "the host is an address that is not on the public internet"
    if name == "localhost" or name.endswith(_LOCAL_SUFFIXES) or "." not in name:
        return "the host is a name for a local or private network"
    return None


_AUTHORITY = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://([^/?#\s]*)")


def url_host(url: str) -> str:
    """The host of ``url`` (no brackets, user information or port), or ``""`` if it has none."""
    m = _AUTHORITY.match(url)
    if m is None:
        return ""
    authority = m.group(1).rpartition("@")[2]
    if authority.startswith("["):
        return authority[1:].partition("]")[0]
    return authority.partition(":")[0]
