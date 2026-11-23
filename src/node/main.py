"""App factory and boot sequence.

Boot order: load registries (fail fast) -> open chain store -> reload keys + validated
chain (missing chain fails closed unless INIT_CHAIN; INIT_CHAIN is ignored when a chain is
persisted) -> cross-check key stores against the registries -> bounded startup sync with peers
(`STARTUP_SYNC_TIMEOUT_S`) -> serve (API writes, mining). Exactly one of expected_difficulty
(pow) / ValidatorSet (pbft) is passed to the core, per CONSENSUS_MODE.
"""

from __future__ import annotations

import asyncio
import logging
from collections import OrderedDict
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from blockchain_core import Block, public_key_from_pem
from blockchain_core.keys import PublicKey
from node.api.chain import router as chain_router
from node.api.documents import router as documents_router
from node.api.metrics import router as metrics_router
from node.api.node_info import router as node_info_router
from node.api.peers import PeerOut, gossip_accept, own_entry, validator_key_now
from node.api.peers import now_ms as wall_ms
from node.api.peers import router as peers_router
from node.body_limit import DEFAULT_BODY_LIMIT, PEER_REGISTER_BODY_LIMIT, BodyLimitMiddleware
from node.config import NodeConfig, load_config
from node.consensus.base import ConsensusEngine
from node.consensus.pbft.engine import PbftEngine
from node.consensus.pbft.forward import (
  ForwardChannel,
  RecordIntake,
  WsRecordForwarder,
  is_forward_message,
)
from node.consensus.pbft.state_store import PbftStateStore, state_path_for
from node.consensus.pow import PowEngine
from node.context import BootError, NodeContext, build_node_context
from node.errors import install_error_handlers
from node.forwarding import (
  PrimaryStatus,
  PrimaryStatusProvider,
  RecordForwarder,
  default_primary_status,
)
from node.network.connection_manager import Connector, PeerConnectionManager, now_ms
from node.network.ws_blocks import (
  BlockReceiver,
  WebsocketsConnector,
  broadcast_block,
)
from node.network.ws_blocks import router as ws_blocks_router
from node.network.ws_pbft import PbftReceiver, is_pbft_message
from node.peers.seed_registration import PeerTransport, UrllibTransport, register_with_seeds
from node.sync import ChainFetcher, ChainSync, HttpChainFetcher, PeerAddress

logger = logging.getLogger("node")

__all__ = [
  "BootError",
  "JudgedSet",
  "NodeContext",
  "app_from_env",
  "build_node_context",
  "create_app",
]

JUDGED_MAX = 4096  # (index, hash) pairs remembered by the equivocation judge


class JudgedSet:
  """A bounded LRU of already-judged keys: a full set evicts its oldest entry, so the judge
  keeps working after `max_size` distinct conflicts instead of going blind."""

  def __init__(self, max_size: int = JUDGED_MAX) -> None:
    if max_size < 1:
      raise ValueError("max_size must be >= 1")
    self._max = max_size
    self._items: OrderedDict[tuple[int, str], None] = OrderedDict()

  def __len__(self) -> int:
    return len(self._items)

  def __contains__(self, key: object) -> bool:
    return key in self._items

  def add(self, key: tuple[int, str]) -> bool:
    """True when `key` is new (and now remembered); False when it was already judged."""
    if key in self._items:
      self._items.move_to_end(key)
      return False
    self._items[key] = None
    if len(self._items) > self._max:
      self._items.popitem(last=False)
    return True


def _log_startup_failure(task: asyncio.Task[None]) -> None:
  if task.cancelled():
    return
  exc = task.exception()
  if exc is not None:  # the node stays not serving (503 not_ready); say why
    logger.error(
      "startup failed, the node is NOT serving: %s: %s",
      type(exc).__name__,
      exc,
      exc_info=exc,
    )


def create_app(
  config: NodeConfig,
  *,
  peer_transport: PeerTransport | None = None,
  sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
  forwarder: RecordForwarder | None = None,
  primary_status: PrimaryStatusProvider | None = None,
  mine: bool = True,
  connector: Connector | None = None,
  network_options: dict[str, Any] | None = None,
  chain_fetcher: ChainFetcher | None = None,
) -> FastAPI:
  pbft_engine: PbftEngine | None = None

  def engine_primary_status() -> PrimaryStatus:
    # Under PBFT the engine knows the primary: self / other / none during a view change.
    if pbft_engine is None:
      return default_primary_status()
    kind, primary = pbft_engine.primary_status()
    if kind == "self":
      return PrimaryStatus.self_()
    if kind == "other" and primary is not None:
      return PrimaryStatus.other(primary)
    return PrimaryStatus.none()

  is_pbft = config.consensus_mode == "pbft" and mine
  context = build_node_context(
    config,
    forwarder=forwarder,
    primary_status=primary_status or (engine_primary_status if is_pbft else None),
  )  # fail fast at construction, not on first request

  def lookup_key(node_id: str) -> PublicKey | None:
    # Connection identity: a ValidatorSet key, else a registered PeerInfo key. Block
    # authorship is stricter (ValidatorSet only) and is judged by the validation gateway.
    resolver = context.resolvers.current
    if node_id in resolver.known_node_ids:  # a validator id is never answered from PeerInfo
      return resolver.resolve_node_key(node_id, now_ms())
    info = next((p for p in context.peers.list() if p.node_id == node_id), None)
    return public_key_from_pem(info.public_key.encode("ascii")) if info is not None else None

  def is_validator(node_id: str) -> bool:
    return node_id in context.resolvers.current.active_node_ids

  async def dispatch(peer_id: str, message: dict[str, Any]) -> None:
    # the receivers are built below, before the manager can deliver a message (in start())
    if is_pbft_message(message):
      await pbft_receiver.on_message(peer_id, message)
    elif is_forward_message(message):
      await forward_channel.on_message(peer_id, message)
    else:
      await receiver.on_message(peer_id, message)

  manager = PeerConnectionManager(
    self_id=config.node_id,
    node_key=context.state.node_key.private_key,
    lookup_key=lookup_key,
    peer_addresses=lambda: [(p.node_id, p.host, p.port) for p in context.peers.list()],
    known_ids=lambda: context.resolvers.current.active_node_ids,
    connector=connector or WebsocketsConnector(allow_loopback=config.allow_loopback_peers),
    on_message=dispatch,
    sleep=sleep,
    **(network_options or {}),
  )
  # our own fetcher owns its request pools: closed on shutdown (an injected one is the caller's)
  own_fetcher: HttpChainFetcher | None = None
  fetcher: ChainFetcher
  if chain_fetcher is None:
    fetcher = own_fetcher = HttpChainFetcher(allow_loopback=config.allow_loopback_peers)
  else:
    fetcher = chain_fetcher
  sync = ChainSync(
    state=context.chain_state,
    validator=context.validator,
    gateway=context.gateway,
    mode=config.consensus_mode,
    peers=lambda: [PeerAddress(p.node_id, p.host, p.port) for p in context.peers.list()],
    fetcher=fetcher,
    flag=manager.flag,
    page_size=config.max_page_size,
    expected_difficulty=config.expected_difficulty,
    # startup is confirmed only by a ValidatorSet member, never by an arbitrary PeerInfo entry
    is_validator=is_validator,
    sleep=sleep,
  )
  announcements: set[asyncio.Task[None]] = set()
  engine: ConsensusEngine | None = None

  async def announce(block: Block) -> None:
    # fire and forget: one slow peer must not delay the next block
    task = asyncio.create_task(broadcast_block(manager, block))
    announcements.add(task)
    task.add_done_callback(announcements.discard)

  if mine and config.consensus_mode == "pow":  # also on an invalid chain: sync may heal it
    engine = PowEngine(context, on_block_mined=announce)
  elif mine:  # pbft: votes go to ValidatorSet members only, never to PeerInfo peers

    async def send_votes(message: dict[str, Any], targets: Any = None) -> None:
      members = context.resolvers.current.active_node_ids
      only = members if targets is None else set(targets) & members
      await manager.broadcast(message, only=only)

    def peers_up() -> set[str]:
      return {node_id for node_id, status in manager.health().items() if status == "up"}

    try:  # fails closed on a missing / unreadable PBFT state file
      pbft_engine = PbftEngine(
        context,
        send=send_votes,
        on_finalized=announce,  # finalized blocks also reach non-validators and lagging nodes
        flag=manager.flag,
        on_needs_sync=sync.request,
        peer_up=peers_up,
        state_store=PbftStateStore(state_path_for(config.chain_path)),
        round_timeout_s=config.pbft_round_timeout_s,
        allow_missing_state=config.pbft_allow_missing_state,
        reset_byzantine_events=config.byzantine_reset_on_boot,
      )
    except Exception:
      context.store.close()  # the boot failed: release the chain store lock
      raise
    engine = pbft_engine

  judged = JudgedSet()  # (index, hash) already judged: no repeated work, oldest evicted

  async def judge_conflict(peer_id: str, block: Block) -> None:
    offenders = await asyncio.to_thread(context.gateway.finalized_conflict, block)
    if offenders is not None:
      context.chain_state.report_byzantine_event(
        f"two finalized blocks at height {block.index} (received from {peer_id}); "
        f"members that committed to both: {sorted(offenders)}",
        offender=",".join(sorted(offenders)) or None,
      )

  def on_equivocation(peer_id: str, block: Block) -> None:
    # UC-8-E4: a different block at a finalized height. A Byzantine event only when BOTH are
    # finalized (quorum-signed): a relayed unfinalized candidate proves nothing. The culprits
    # are the members whose commits are on both blocks, whoever proposed them.
    if not judged.add((block.index, block.block_hash)):
      return
    task = asyncio.create_task(judge_conflict(peer_id, block))
    announcements.add(task)
    task.add_done_callback(announcements.discard)

  receiver = BlockReceiver(
    context.gateway,
    engine,
    manager,
    on_needs_sync=sync.request,
    on_equivocation=on_equivocation if pbft_engine is not None else None,
  )
  pbft_receiver = PbftReceiver(pbft_engine, is_validator=is_validator, flag=manager.flag)

  async def send_direct(message: dict[str, Any], targets: Any) -> dict[str, bool]:
    return await manager.broadcast(message, only=targets)

  intake = None
  if pbft_engine is not None:
    running = pbft_engine
    intake = RecordIntake(
      context,
      lookup_key=lookup_key,
      is_validator=is_validator,
      is_primary=lambda: running.primary_status()[0] == "self",
      on_queued=running.on_submission,
      accepting=lambda: bool(getattr(app.state, "accepting", False)),
    )
  forward_channel = ForwardChannel(
    intake=intake, pending=context.forwarding.pending, send=send_direct, flag=manager.flag
  )
  if pbft_engine is not None and forwarder is None:
    context.forwarding.use(
      WsRecordForwarder(
        self_id=config.node_id,
        key=context.state.node_key.private_key,
        send=send_direct,
        channel=lambda: forward_channel,
      )
    )

  @asynccontextmanager
  async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    task: asyncio.Task[None] | None = None
    background: set[asyncio.Task[None]] = set()

    async def go_live() -> None:
      """load (done) -> bounded startup sync -> serve; then keep syncing in the background."""
      if config.seed_peers or len(context.peers):
        logger.info("startup sync (up to %ss)", config.startup_sync_timeout_s)
        await sync.startup(config.startup_sync_timeout_s)
      if engine is not None:
        await engine.start()
      app.state.accepting = True
      logger.info("node %s is serving", config.node_id)
      periodic = asyncio.create_task(sync.run(config.sync_interval_s), name="chain-sync")
      background.add(periodic)

    await manager.start()
    if config.seed_peers:
      task = asyncio.create_task(
        register_with_seeds(
          config.seed_peers,
          # rebuilt per attempt: every (re-)registration carries a fresh signed issued_at
          lambda: own_entry(context, wall_ms()).model_dump(exclude={"last_seen"}),
          context.peers,
          peer_transport or UrllibTransport(),
          PeerOut,
          sleep=sleep,
          accept=gossip_accept(context),
          key_now=validator_key_now(context),
        )
      )
    if config.seed_peers or len(context.peers):
      startup = asyncio.create_task(go_live(), name="startup-sync")  # serve 503 meanwhile
      startup.add_done_callback(_log_startup_failure)
      background.add(startup)
    else:
      await go_live()  # no peer to wait for
    try:
      yield
    finally:
      app.state.accepting = False
      for job in list(background):  # sync stops before the store closes
        job.cancel()
      await asyncio.gather(*background, return_exceptions=True)
      if engine is not None:
        await engine.stop()
      await forward_channel.stop()
      pending = list(announcements)
      for announcement in pending:
        announcement.cancel()
      await asyncio.gather(*pending, return_exceptions=True)
      await manager.stop()
      if task is not None:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
      if own_fetcher is not None:
        own_fetcher.close()
      context.store.close()

  app = FastAPI(title="Document verification node", lifespan=lifespan)
  app.state.context = context
  app.state.engine = engine
  app.state.manager = manager
  app.state.receiver = receiver
  app.state.pbft_receiver = pbft_receiver
  app.state.forward_channel = forward_channel
  app.state.sync = sync
  app.state.accepting = False  # nothing is served before the startup sync (UC-3-F)
  install_error_handlers(app)
  app.include_router(node_info_router)
  app.include_router(peers_router)
  app.include_router(chain_router)
  app.include_router(documents_router)
  app.include_router(metrics_router)
  app.include_router(ws_blocks_router)
  # Every request body is capped (DEFAULT_BODY_LIMIT unless listed). JSON escapes can inflate
  # metadata up to ~3x its canonical size; 4x plus slack is safe for /documents.
  app.add_middleware(
    BodyLimitMiddleware,
    limits={
      "/documents": 4 * config.max_metadata_bytes + 1024,
      "/peers/register": PEER_REGISTER_BODY_LIMIT,
    },
    default=DEFAULT_BODY_LIMIT,
  )
  app.add_middleware(
    CORSMiddleware,
    allow_origins=list(config.cors_origins),
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
  )
  return app


def app_from_env() -> FastAPI:
  """`uvicorn node.main:app_from_env --factory`"""
  return create_app(load_config())
