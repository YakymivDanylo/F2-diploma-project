"""The interface both consensus algorithms implement, so CONSENSUS_MODE picks one."""

from __future__ import annotations

from typing import Protocol

from blockchain_core import Block, DocumentRecord


class ConsensusEngine(Protocol):
  def on_submission(self, record: DocumentRecord) -> None:
    """A record entered this node's mempool; wake the engine. Must not block."""

  async def on_inbound_block(self, block: Block) -> bool:
    """Offer a block received from a peer. True when it was adopted as the new tip."""

  async def start(self) -> None: ...

  async def stop(self) -> None: ...
