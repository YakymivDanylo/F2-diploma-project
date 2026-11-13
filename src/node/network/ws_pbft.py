"""PBFT messages on the authenticated peer links.

As built, PBFT messages are multiplexed over the same authenticated, MAC'd peer link as block
pushes (one link per peer, dialed at `/ws/blocks`) instead of a second socket at `/ws/pbft`:
one handshake path, one reconnect/backoff state and one health entry per peer. Messages are
told apart by their `type`.

The receiver runs on the link's read loop, so it only does cheap work: it drops PBFT traffic
from peers outside the active ValidatorSet, decodes the message strictly, binds the signed
`node_id` to the authenticated link identity, and enqueues it for the engine task. A node
that runs no PBFT engine (PoW mode) ignores PBFT messages with no state change.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from node.consensus.pbft.messages import MalformedMessage, decode_message

if TYPE_CHECKING:
  from node.consensus.pbft.engine import PbftEngine

PBFT_PREFIX = "pbft_"


def is_pbft_message(message: dict[str, Any]) -> bool:
  kind = message.get("type")
  return isinstance(kind, str) and kind.startswith(PBFT_PREFIX)


class PbftReceiver:
  def __init__(
    self,
    engine: PbftEngine | None,
    *,
    is_validator: Callable[[str], bool],
    flag: Callable[[str, str], None],
  ) -> None:
    self._engine = engine
    self._is_validator = is_validator
    self._flag = flag

  async def on_message(self, peer_id: str, raw: dict[str, Any]) -> None:
    if self._engine is None:
      return  # no PBFT here (PoW mode): ignored, nothing changes
    if not self._is_validator(peer_id):
      self._flag(peer_id, "pbft message from a non-validator link")
      return
    try:
      message = decode_message(raw)
    except MalformedMessage as exc:
      self._flag(peer_id, f"malformed pbft message: {exc}")
      return
    if message.node_id != peer_id:  # a vote is only ever accepted from its own signer's link
      self._flag(peer_id, "pbft node_id does not match the authenticated link")
      return
    self._engine.submit(message)
