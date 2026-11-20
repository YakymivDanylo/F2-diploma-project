"""Outbound address guard: never poll or dial an address that resolves somewhere it must not.

`peer_address_problem` (node.peers.registry) judges the address a peer ADVERTISES; a DNS name
passes it unchecked (docker service names such as `node2` are legitimate). This module closes
that gap at the moment we actually connect: `check_resolved` resolves the host and refuses it
if ANY resolved address is loopback, link-local, unspecified (all of 0.0.0.0/8, "this
network"), multicast, IPv4-compatible IPv6 (::/96, e.g. ::7f00:1 = ::127.0.0.1) or a cloud
metadata endpoint. Cloud metadata: the IPv4 one (169.254.169.254) is link-local; the IPv6 one
(AWS fd00:ec2::254) sits in the unique-local range, so it is listed explicitly. IPv4-mapped
addresses (::ffff:127.0.0.1) are judged as the IPv4 address they carry. `allow_loopback`
(config `ALLOW_LOOPBACK_PEERS`, local single-machine development only) admits loopback and
nothing else. A literal IP is judged directly, without a lookup.

Resolution from async code (`check_resolved_async`) never touches the shared default executor
(ChainState append / replace, store.save and the prechecks run there): it uses two small
dedicated pools - one for validator traffic, one for everyone else - so slow name servers
behind up to 64 non-validator dial loops can neither starve mining / PBFT / sync nor delay a
validator's lookup. Each lookup is bounded by `RESOLVE_TIMEOUT_S`, and a successful result is
cached for `RESOLVE_CACHE_TTL_S`. Which pool serves a call is set by the `validator_traffic`
context variable (`prioritized(...)`): the dial loop and the chain sync set it per peer.

The resolver pools and the lookup cache are module-level, i.e. PROCESS-WIDE by design: one node
runs per process, they live as long as it does, and every DNS name is judged by the same cache
(tests reset it with `clear_resolution_cache()`). Per-client resources - the chain fetcher's
request pools - belong to their instance instead (`HttpChainFetcher.close()`).

The resolver is injectable, so tests never need real DNS.

Residual risk - DNS rebinding: the check resolves the name, and the HTTP / WebSocket client
then resolves it AGAIN when it opens the socket. A hostile DNS server with a zero TTL can
answer the check with a public address and the connect with 127.0.0.1. Closing that fully
needs connecting to the exact address that was checked (pinning the resolved IP, with the
original name kept for the Host header / TLS SNI) - deferred to the Epic 6 TLS client factory.
Until then the guard stops static misdirection (a name that simply points at loopback,
link-local or metadata addresses), not an active rebinding attacker who controls a DNS zone.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import socket
import time
from collections import OrderedDict
from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextvars import ContextVar

IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Resolver = Callable[[str, int], Iterable[str]]
"""`resolve(host, port)` -> the IP address strings the host resolves to (OSError on failure)."""

RESOLVE_TIMEOUT_S = 5.0  # one lookup; a hung name server costs a caller at most this long
RESOLVE_CACHE_TTL_S = 30.0  # successful lookups only: a failure is retried by the caller
RESOLVE_CACHE_SIZE = 1024
RESOLVE_WORKERS = 4  # non-validator lookups
PRIORITY_RESOLVE_WORKERS = 2  # validator lookups: never queued behind the others
_THIS_NETWORK = ipaddress.ip_network("0.0.0.0/8")
_IPV4_COMPATIBLE = ipaddress.ip_network("::/96")  # deprecated ::a.b.c.d form
_CLOUD_METADATA = (ipaddress.ip_network("fd00:ec2::254/128"),)  # IPv4 one is link-local

validator_traffic: ContextVar[bool] = ContextVar("validator_traffic", default=False)
"""True while the current task talks to a ValidatorSet member: its lookups (and the chain
fetcher's requests) use the reserved pools. Set it with `prioritized`."""

# process-wide by design (see the module doc): never shut down while the process runs
_pools = {
  True: ThreadPoolExecutor(PRIORITY_RESOLVE_WORKERS, thread_name_prefix="dns-validator"),
  False: ThreadPoolExecutor(RESOLVE_WORKERS, thread_name_prefix="dns"),
}
_cache: OrderedDict[tuple[Resolver, str, int], tuple[float, tuple[str, ...]]] = OrderedDict()


class UnsafeAddressError(OSError):
  """The peer's host is, or resolves to, an address we never connect to. An `OSError`, so
  every dial / fetch path treats it like any other unreachable address."""


@contextlib.contextmanager
def prioritized(validator: bool) -> Iterator[None]:
  """Mark the enclosed (async) code as validator traffic or not (see `validator_traffic`)."""
  token = validator_traffic.set(validator)
  try:
    yield
  finally:
    validator_traffic.reset(token)


def system_resolve(host: str, port: int) -> list[str]:
  """`socket.getaddrinfo` (blocking: call it from a worker thread)."""
  infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
  return [str(info[4][0]) for info in infos]


def clear_resolution_cache() -> None:
  _cache.clear()


def _literal(host: str) -> IpAddress | None:
  name = host.strip().strip("[]")
  try:
    return ipaddress.ip_address(name)
  except ValueError:
    return None


def _problem(ip: IpAddress, *, allow_loopback: bool) -> str | None:
  if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
    ip = ip.ipv4_mapped  # ::ffff:127.0.0.1 is 127.0.0.1
  if ip.is_loopback:
    return None if allow_loopback else "loopback"
  if any(ip in network for network in _CLOUD_METADATA):
    return "cloud-metadata"
  if ip.is_link_local:
    return "link-local"  # incl. the IPv4 cloud-metadata address 169.254.169.254
  if ip.is_unspecified or ip in _THIS_NETWORK:
    return "unspecified"
  if ip in _IPV4_COMPATIBLE:
    return "IPv4-compatible"  # ::7f00:1 is ::127.0.0.1 (:: and ::1 are judged above)
  if ip.is_multicast:
    return "multicast"
  return None


def _judge(host: str, raw: Iterable[str], *, allow_loopback: bool) -> None:
  addresses: list[IpAddress] = []
  for item in raw:
    ip = _literal(item.split("%", 1)[0])  # drop an IPv6 zone id ("fe80::1%eth0")
    if ip is None:
      raise UnsafeAddressError(f"{host!r} resolved to an unparseable address")
    addresses.append(ip)
  if not addresses:
    raise UnsafeAddressError(f"{host!r} resolved to no address")
  for ip in addresses:
    problem = _problem(ip, allow_loopback=allow_loopback)
    if problem is not None:
      raise UnsafeAddressError(
        f"refusing to connect to {host!r}: it resolves to a {problem} address ({ip})"
      )


def check_resolved(
  host: str,
  port: int,
  *,
  allow_loopback: bool,
  resolve: Resolver = system_resolve,
) -> None:
  """Raise `UnsafeAddressError` if `host` is, or resolves to (any one of its addresses), a
  forbidden address (see the module docstring; loopback is admitted with `allow_loopback`).
  A failed lookup propagates as its own `OSError` (socket.gaierror). Blocking when it
  resolves, uncached and unbounded: async code uses `check_resolved_async`."""
  literal = _literal(host)
  if literal is not None:
    _judge(host, [str(literal)], allow_loopback=allow_loopback)
    return
  _judge(host, resolve(host, port), allow_loopback=allow_loopback)


async def check_resolved_async(
  host: str,
  port: int,
  *,
  allow_loopback: bool,
  resolve: Resolver = system_resolve,
  timeout: float | None = None,
) -> None:
  """`check_resolved` from async code: a literal IP is judged inline; a name is resolved on a
  dedicated pool (the validator one when `validator_traffic` is set), bounded by `timeout`
  (default `RESOLVE_TIMEOUT_S`; a `TimeoutError`, i.e. an OSError, when it runs out) and
  cached for `RESOLVE_CACHE_TTL_S`, so a slow DNS server stalls neither the event loop nor
  the shared default executor."""
  if _literal(host) is not None:
    check_resolved(host, port, allow_loopback=allow_loopback, resolve=resolve)
    return
  key = (resolve, host, port)
  now = time.monotonic()
  cached = _cache.get(key)
  if cached is not None and cached[0] > now:
    _cache.move_to_end(key)
    raw = cached[1]
  else:
    loop = asyncio.get_running_loop()
    pool = _pools[validator_traffic.get()]
    limit = RESOLVE_TIMEOUT_S if timeout is None else timeout
    try:
      # a timeout cancels a queued lookup; one already running finishes in its thread
      raw = await asyncio.wait_for(
        loop.run_in_executor(pool, lambda: tuple(resolve(host, port))), limit
      )
    except TimeoutError:
      raise TimeoutError(f"resolving {host!r} took longer than {limit}s") from None
    _cache[key] = (time.monotonic() + RESOLVE_CACHE_TTL_S, raw)
    _cache.move_to_end(key)
    while len(_cache) > RESOLVE_CACHE_SIZE:
      _cache.popitem(last=False)
  _judge(host, raw, allow_loopback=allow_loopback)
