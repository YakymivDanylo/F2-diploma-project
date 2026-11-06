"""PeerInfo registry: dynamic, gossip-populated, connectivity only.

Deliberately imports nothing from `node.registries`: the ValidatorSet (quorum) and this
registry are structurally disconnected, so peer growth can never change n, f or a quorum.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, replace


class PeerKeyMismatchError(ValueError):
  """A known node_id re-registered with a different public key."""


@dataclass(frozen=True)
class PeerInfo:
  node_id: str
  host: str
  port: int
  public_key: str  # PEM of the peer's NodeKeyPair public key
  last_seen: int  # epoch ms


class PeerRegistry:
  def __init__(self, self_id: str) -> None:
    self._self_id = self_id
    self._peers: dict[str, PeerInfo] = {}

  def register(self, node_id: str, host: str, port: int, public_key: str) -> PeerInfo | None:
    """Add or refresh a peer. Self is ignored (None). A different key for a known id raises."""
    if node_id == self._self_id:
      return None
    now = int(time.time() * 1000)
    existing = self._peers.get(node_id)
    if existing is None:
      info = PeerInfo(node_id, host, port, public_key, now)
    elif existing.public_key != public_key:
      raise PeerKeyMismatchError(node_id)
    else:
      info = replace(existing, host=host, port=port, last_seen=now)
    self._peers[node_id] = info
    return info

  def list(self) -> list[PeerInfo]:
    return list(self._peers.values())

  def __len__(self) -> int:
    return len(self._peers)
