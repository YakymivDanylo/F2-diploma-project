"""WS /ws/blocks: push finalized blocks to peers, and judge blocks pushed to us.

Receiving a block never trusts the sender: it is decoded, then screened by the single
validation gateway, and only then handed to the consensus engine. A rejected block is never
appended and never forwarded. Accepted blocks are not relayed either - the manager keeps a
link to every known peer (full mesh), and a peer that missed a block catches up by chain
sync (`node.sync`), which a `needs_sync` verdict triggers on demand.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from blockchain_core import Block
from blockchain_core.storage.chain_store import block_from_dict, block_to_dict
from node.network.connection_manager import (
  BLOCKS_PATH,
  MAX_MESSAGE_BYTES,
  ConnectionClosed,
  PeerConnectionManager,
)
from node.validation_gateway import InboundVerdict, ValidationGateway

if TYPE_CHECKING:
  from node.consensus.base import ConsensusEngine

logger = logging.getLogger("node.blocks")
router = APIRouter()
MAX_SYNC_HINTS = 64


class StarletteWs:
  """Adapts a Starlette WebSocket to the manager's `WsLike`."""

  def __init__(self, websocket: WebSocket) -> None:
    self._ws = websocket

  async def send_text(self, data: str) -> None:
    try:
      await self._ws.send_text(data)
    except (WebSocketDisconnect, RuntimeError):
      raise ConnectionClosed from None

  async def receive_text(self) -> str:
    try:
      text = await self._ws.receive_text()
    except (WebSocketDisconnect, RuntimeError):
      raise ConnectionClosed from None
    if len(text) > MAX_MESSAGE_BYTES:
      await self.close(1009)
      raise ConnectionClosed
    return text

  async def close(self, code: int = 1000) -> None:
    try:
      await self._ws.close(code)
    except RuntimeError:
      pass  # already closed


class WebsocketsConnector:
  """Outbound dialer over the `websockets` library."""

  async def connect(self, host: str, port: int, path: str) -> Any:
    from websockets.asyncio.client import connect
    from websockets.exceptions import WebSocketException

    try:
      raw = await connect(f"ws://{host}:{port}{path}", max_size=MAX_MESSAGE_BYTES, open_timeout=5)
    except (WebSocketException, TimeoutError) as exc:
      raise ConnectionClosed from exc
    return _WebsocketsWs(raw)


class _WebsocketsWs:
  def __init__(self, ws: Any) -> None:
    self._ws = ws

  async def send_text(self, data: str) -> None:
    from websockets.exceptions import ConnectionClosed as Closed

    try:
      await self._ws.send(data)
    except Closed:
      raise ConnectionClosed from None

  async def receive_text(self) -> str:
    from websockets.exceptions import ConnectionClosed as Closed

    try:
      message = await self._ws.recv()
    except Closed:
      raise ConnectionClosed from None
    if not isinstance(message, str):
      raise ConnectionClosed  # binary frames are not part of the protocol
    return message

  async def close(self, code: int = 1000) -> None:
    await self._ws.close(code)


class BlockReceiver:
  """Handles `block` messages from authenticated peers."""

  def __init__(
    self,
    gateway: ValidationGateway,
    engine: ConsensusEngine | None,
    manager: PeerConnectionManager,
    *,
    on_needs_sync: Callable[[str], None] | None = None,
  ) -> None:
    self._gateway = gateway
    self._engine = engine
    self._manager = manager
    self._on_needs_sync = on_needs_sync
    self.needs_sync: list[str] = []  # peers that showed a longer chain (bounded audit trail)

  async def on_message(self, peer_id: str, message: dict[str, Any]) -> None:
    if message.get("type") != "block":
      self._manager.flag(peer_id, "unknown_message_type")
      return
    await self.handle_block(peer_id, message.get("block"))

  async def handle_block(self, peer_id: str, payload: object) -> InboundVerdict:
    """Decode -> screen -> adopt. Adoption goes through `ChainState`, which re-checks the tip
    under its lock, so a block screened against a tip that moved meanwhile is not appended."""
    try:
      block = block_from_dict(payload)
    except Exception:
      self._manager.flag(peer_id, "malformed_block")
      return InboundVerdict("reject", "malformed")
    verdict = self._gateway.screen(block)
    if verdict.kind == "duplicate":
      return verdict
    if verdict.kind == "needs_sync":
      logger.info(
        "block %d from %s does not extend our tip; chain sync handles it", block.index, peer_id
      )
      if peer_id not in self.needs_sync and len(self.needs_sync) < MAX_SYNC_HINTS:
        self.needs_sync.append(peer_id)
      if self._on_needs_sync is not None:
        self._on_needs_sync(peer_id)  # on-demand chain sync (UC-3 trigger)
      return verdict
    if verdict.kind == "reject":
      self._manager.flag(peer_id, f"rejected block: {verdict.reason}")
      return verdict
    if self._engine is None or not await self._engine.on_inbound_block(block):
      logger.info("block %d from %s was valid but not adopted", block.index, peer_id)
      return InboundVerdict("reject", "not_adopted")
    return verdict


async def broadcast_block(manager: PeerConnectionManager, block: Block) -> None:
  await manager.broadcast({"type": "block", "block": block_to_dict(block)})


@router.websocket(BLOCKS_PATH)
async def ws_blocks(websocket: WebSocket) -> None:
  manager: PeerConnectionManager | None = websocket.app.state.manager
  await websocket.accept()
  if manager is None or not websocket.app.state.accepting:
    await websocket.close(1013)  # try again later
    return
  await manager.accept_inbound(StarletteWs(websocket))
