"""RecordForwarder contract: a non-primary hands an already-signed record to the primary.

This module defines the interface, the closed reply enum, the primary-status seam and the
pending-request table. The real channel (`forward_record` on the authenticated peer link),
sender authentication and the primary-side acceptance live in `node.consensus.pbft.forward`
and are installed by `node.main` under PBFT. The proposer never re-signs a forwarded record.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal, Protocol

from blockchain_core import DocumentRecord

logger = logging.getLogger("node.forwarding")

# Closed set of primary replies; anything else is a defect (never acceptance).
REPLY_CODES = frozenset(
  {
    "accepted",
    "duplicate",
    "not_primary",
    "not_validator",
    "unregistered_issuer",
    "invalid_record",
    "auth_failed",
  }
)


class ForwardUnavailable(Exception):
  """The primary could not be reached (refused, reset, no established channel)."""


class ForwardTimeout(Exception):
  """No reply within FORWARD_ACK_TIMEOUT_MS."""


class ForwardProtocolError(Exception):
  """The reply was outside the closed enum; treated as a defect, never as acceptance."""


@dataclass(frozen=True)
class PrimaryStatus:
  """Who handles submissions: this node, another node, or nobody (view change)."""

  kind: Literal["self", "other", "none"]
  node_id: str | None = None

  @classmethod
  def self_(cls) -> PrimaryStatus:
    return cls("self")

  @classmethod
  def other(cls, node_id: str) -> PrimaryStatus:
    return cls("other", node_id)

  @classmethod
  def none(cls) -> PrimaryStatus:
    return cls("none")


PrimaryStatusProvider = Callable[[], PrimaryStatus]


def default_primary_status() -> PrimaryStatus:
  """Without a PBFT engine (PoW, or a node that runs no consensus) every node queues locally.
  Under PBFT the engine-backed status replaces it (wired in `node.main`)."""
  return PrimaryStatus.self_()


class RecordForwarder(Protocol):
  async def send(self, request_id: str, record: DocumentRecord, primary_id: str) -> None:
    """Deliver a `forward_record` message. Raise `ForwardUnavailable` if it cannot be sent.

    The reply arrives later through `PendingForwards.resolve(request_id, code)`.
    """


class UnavailableForwarder:
  """The forwarder before (or without) a network: no channel exists, so a forward is a
  connection failure. Under PBFT `node.main` replaces it with `WsRecordForwarder`."""

  async def send(self, request_id: str, record: DocumentRecord, primary_id: str) -> None:
    raise ForwardUnavailable("no forwarding channel to the primary is established")


class PendingForwards:
  """One entry per in-flight request_id; removed on reply or timeout."""

  def __init__(self) -> None:
    self._futures: dict[str, asyncio.Future[object]] = {}

  def register(self, request_id: str) -> asyncio.Future[object]:
    future: asyncio.Future[object] = asyncio.get_running_loop().create_future()
    self._futures[request_id] = future
    return future

  def resolve(self, request_id: str, reply: object) -> bool:
    """Deliver a reply. Unknown or already-settled request ids are dropped (False)."""
    future = self._futures.get(request_id)
    if future is None or future.done():
      logger.warning("dropping forward reply for unknown request_id")
      return False
    future.set_result(reply)
    return True

  def has(self, request_id: str) -> bool:
    future = self._futures.get(request_id)
    return future is not None and not future.done()

  def discard(self, request_id: str) -> None:
    self._futures.pop(request_id, None)

  def __len__(self) -> int:
    return len(self._futures)


class ForwardService:
  def __init__(
    self,
    forwarder: RecordForwarder,
    pending: PendingForwards,
    timeout_ms: int,
    new_request_id: Callable[[], str] = lambda: str(uuid.uuid4()),
  ) -> None:
    self._forwarder = forwarder
    self.pending = pending
    self._timeout_s = timeout_ms / 1000
    self._new_request_id = new_request_id

  def use(self, forwarder: RecordForwarder) -> None:
    """Install the real channel once the network exists (`WsRecordForwarder`)."""
    self._forwarder = forwarder

  async def forward(self, record: DocumentRecord, primary_id: str) -> str:
    """Forward once and await one reply. Returns a code from `REPLY_CODES`."""
    request_id = self._new_request_id()
    future = self.pending.register(request_id)
    try:
      try:
        async with asyncio.timeout(self._timeout_s):  # covers a blocked send as well
          await self._forwarder.send(request_id, record, primary_id)
          reply = await future
      except TimeoutError:
        raise ForwardTimeout(request_id) from None
    finally:
      self.pending.discard(request_id)
    if not isinstance(reply, str) or reply not in REPLY_CODES:
      logger.error("forward reply outside the closed enum")  # never log the payload
      raise ForwardProtocolError("reply outside the closed enum")
    return reply
