"""PeerInfo registry: dynamic, gossip-populated, connectivity only.

Deliberately imports nothing from `node.registries`: the ValidatorSet (quorum) and this
registry are structurally disconnected, so peer growth can never change n, f or a quorum.
Which ids are ValidatorSet identities is passed in as an opaque predicate (`is_protected`):
those entries are never evicted. Every other entry expires when not refreshed within
`PEER_TTL_S`, and a full registry makes room by evicting its stale-most unprotected entry.

Key binding: a non-validator id stays bound to the first key it registered (a different key
raises `PeerKeyMismatchError`). A protected (ValidatorSet) id is bound to whatever key the
ValidatorSet holds for it NOW, which changes on rotation: its entries are never evicted, so a
mismatch rule would pin the retired key forever and lock the rotated validator out (409 on
every registration, and unreachable if its address also moved). The caller verifies every
protected registration with the ValidatorSet key in force now (`check_registration`) before
calling `register`, so the key it passes replaces the stored one.

Registration order: the held registration time never moves back. `PeerInfo.max_issued_at` is
a monotonic high-water mark (only ever increases) that every staleness comparison uses, while
`issued_at` / `signature` stay the pair exactly as signed, for publication in GET /peers.
The attestation check tolerates a registration up to the skew window older than the held one
(a clock step back), but such a registration only refreshes the TTL of the held entry when the
address is unchanged; a changed address needs `issued_at >= held` (`StaleRegistrationError`).
Otherwise replaying the public older registrations (GET /peers publishes issued_at and
signature) could walk the held `issued_at` back one skew window at a time and keep a moved
peer's old address alive. A rotated validator key at the same address stores the older
(issued_at, signature) pair it was signed with - but the high-water mark stays, so that never
opens the walk-back either.
"""

from __future__ import annotations

import ipaddress
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace

PEER_TTL_S = 600  # a non-validator entry not refreshed for this long is evicted
DEFAULT_MAX_PEERS = 256


class PeerRegistryFullError(RuntimeError):
  """The registry is full of protected (ValidatorSet) entries; a new id cannot be added."""


class PeerKeyMismatchError(ValueError):
  """A known node_id re-registered with a different public key."""


class StaleRegistrationError(ValueError):
  """A registration older than the held one tried to change the peer's address."""


def _is_older(issued_at: int | None, held_issued_at: int | None) -> bool:
  """Whether a signed registration is older than the held one (unsigned: no order)."""
  return issued_at is not None and held_issued_at is not None and issued_at < held_issued_at


def _newest(issued_at: int | None, held_issued_at: int | None) -> int | None:
  if issued_at is None or held_issued_at is None:
    return issued_at if held_issued_at is None else held_issued_at
  return max(issued_at, held_issued_at)


@dataclass(frozen=True)
class PeerInfo:
  node_id: str
  host: str
  port: int
  public_key: str  # PEM of the peer's NodeKeyPair public key
  last_seen: int  # epoch ms of the last registration / refresh
  issued_at: int | None = None  # signed registration (published with `signature` as signed)
  signature: str | None = None
  # the newest issued_at ever held for this id: the staleness bound, never moves back
  max_issued_at: int | None = field(default=None, compare=False)

  @property
  def held_issued_at(self) -> int | None:
    """The issued_at a new registration is judged against (the high-water mark)."""
    if self.max_issued_at is None:
      return self.issued_at
    if self.issued_at is None:
      return self.max_issued_at
    return max(self.max_issued_at, self.issued_at)


def _wall_ms() -> int:
  return int(time.time() * 1000)


def _never(_node_id: str) -> bool:
  return False


def _literal_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
  try:
    return ipaddress.ip_address(host)
  except ValueError:
    pass
  try:  # legacy IPv4 forms the resolver also accepts: "127.1", "2130706433", "0x7f.0.0.1"
    return ipaddress.IPv4Address(socket.inet_aton(host))
  except (OSError, ValueError):
    return None


def _normalized_host(host: str) -> str:
  return host.strip().lower().rstrip(".")


def is_loopback_host(host: str) -> bool:
  """`localhost`, `*.localhost` or a literal loopback IP address."""
  name = _normalized_host(host)
  if name == "localhost" or name.endswith(".localhost"):
    return True
  ip = _literal_ip(name)
  return ip is not None and ip.is_loopback


def peer_address_problem(
  host: str,
  port: int,
  *,
  own_host: str,
  own_port: int,
  allow_loopback: bool = False,
) -> str | None:
  """Why a peer address must not be stored (None when it is acceptable). Private ranges and
  DNS names (docker service names) are fine; loopback can be allowed for local development."""
  name = _normalized_host(host)
  if name == _normalized_host(own_host) and port == own_port:
    return "the address is this node's own address"
  if not allow_loopback and is_loopback_host(name):
    return "loopback addresses are not accepted"
  ip = _literal_ip(name)
  if ip is not None and not ip.is_loopback:
    if ip.is_link_local or ip.is_unspecified or ip.is_multicast:
      return "link-local, unspecified and multicast addresses are not accepted"
  return None


class PeerRegistry:
  def __init__(
    self,
    self_id: str,
    max_peers: int = DEFAULT_MAX_PEERS,
    *,
    is_protected: Callable[[str], bool] | None = None,
    ttl_ms: int = PEER_TTL_S * 1000,
    clock: Callable[[], int] = _wall_ms,
  ) -> None:
    self._self_id = self_id
    self._max_peers = max_peers
    self._is_protected = is_protected or _never
    self._ttl_ms = ttl_ms
    self._clock = clock
    self._peers: dict[str, PeerInfo] = {}

  def register(
    self,
    node_id: str,
    host: str,
    port: int,
    public_key: str,
    *,
    issued_at: int | None = None,
    signature: str | None = None,
  ) -> PeerInfo | None:
    """Add or refresh a peer. Self is ignored (None).

    A different key for a known non-validator id raises `PeerKeyMismatchError`; for a
    protected (ValidatorSet) id it replaces the stored key (rotation, see the module doc).
    A registration older than the held one that changes host:port raises
    `StaleRegistrationError`; with the same address it only refreshes `last_seen`.
    The caller (the API / gossip merge) has already checked the signed registration, for a
    protected id against the ValidatorSet key in force now."""
    if node_id == self._self_id:
      return None
    now = self._clock()
    self._evict_stale(now)
    existing = self._peers.get(node_id)
    if existing is None:
      if len(self._peers) >= self._max_peers:
        self._make_room(node_id)
      info = PeerInfo(node_id, host, port, public_key, now, issued_at, signature, issued_at)
    elif existing.public_key != public_key and not self._is_protected(node_id):
      raise PeerKeyMismatchError(node_id)
    elif _is_older(issued_at, existing.held_issued_at):
      # Inside the skew tolerance of the attestation check (clock step back): never a move.
      if (host, port) != (existing.host, existing.port):
        raise StaleRegistrationError(node_id)
      if public_key == existing.public_key:  # a TTL refresh: the held registration stays
        info = replace(existing, last_seen=now)
      else:  # a rotated validator key, same address: the (key, signature) pair must match
        info = replace(  # ... while the high-water mark stays where it was
          existing,
          public_key=public_key,
          last_seen=now,
          issued_at=issued_at,
          signature=signature,
          max_issued_at=existing.held_issued_at,
        )
    else:
      info = replace(
        existing,
        host=host,
        port=port,
        public_key=public_key,
        last_seen=now,
        issued_at=issued_at,
        signature=signature,
        max_issued_at=_newest(issued_at, existing.held_issued_at),
      )
    self._peers[node_id] = info
    return info

  def is_protected(self, node_id: str) -> bool:
    return self._is_protected(node_id)

  def get(self, node_id: str) -> PeerInfo | None:
    self._evict_stale(self._clock())
    return self._peers.get(node_id)

  def list(self) -> list[PeerInfo]:
    self._evict_stale(self._clock())
    return list(self._peers.values())

  def __len__(self) -> int:
    self._evict_stale(self._clock())
    return len(self._peers)

  def _evict_stale(self, now: int) -> None:
    expired = [
      node_id
      for node_id, info in self._peers.items()
      if now - info.last_seen > self._ttl_ms and not self._is_protected(node_id)
    ]
    for node_id in expired:
      del self._peers[node_id]

  def _make_room(self, node_id: str) -> None:
    candidates = [info for info in self._peers.values() if not self._is_protected(info.node_id)]
    if not candidates:
      raise PeerRegistryFullError(node_id)
    stalest = min(candidates, key=lambda info: info.last_seen)
    del self._peers[stalest.node_id]
