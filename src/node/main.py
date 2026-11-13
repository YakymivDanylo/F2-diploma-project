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
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from blockchain_core import (
  Block,
  JsonChainStore,
  NodeState,
  public_key_from_pem,
  public_key_to_pem,
  restore_node_state,
)
from blockchain_core.keys import PublicKey
from node.api.chain import router as chain_router
from node.api.documents import router as documents_router
from node.api.metrics import router as metrics_router
from node.api.node_info import router as node_info_router
from node.api.peers import PeerOut, own_entry, validator_registration_error
from node.api.peers import now_ms as wall_ms
from node.api.peers import router as peers_router
from node.body_limit import BodyLimitMiddleware
from node.chain_state import ChainState
from node.config import NodeConfig, load_config
from node.consensus.base import ConsensusEngine
from node.consensus.pbft.engine import PbftEngine
from node.consensus.pow import PowEngine
from node.errors import install_error_handlers
from node.forwarding import (
  ForwardService,
  PendingForwards,
  PrimaryStatusProvider,
  RecordForwarder,
  UnavailableForwarder,
  default_primary_status,
)
from node.key_resolver import CombinedKeyResolver, ResolverHolder
from node.mempool import DocumentIndex, Mempool
from node.metrics import MetricsRecorder
from node.network.connection_manager import Connector, PeerConnectionManager, now_ms
from node.network.ws_blocks import (
  BlockReceiver,
  WebsocketsConnector,
  broadcast_block,
)
from node.network.ws_blocks import router as ws_blocks_router
from node.network.ws_pbft import PbftReceiver, is_pbft_message
from node.peers.registry import PeerRegistry
from node.peers.seed_registration import PeerTransport, UrllibTransport, register_with_seeds
from node.registries import (
  IssuerRegistry,
  ValidatorRegistry,
  active_entry,
  load_issuer_registry,
  load_validator_registry,
)
from node.sync import ChainFetcher, ChainSync, HttpChainFetcher, PeerAddress
from node.validation_gateway import ChainValidator, ValidationGateway
from node.validity_cache import ValidityCache

logger = logging.getLogger("node")


class BootError(RuntimeError):
  """Key stores and registries disagree; the node must not start."""


@dataclass(frozen=True)
class NodeContext:
  config: NodeConfig
  validators: ValidatorRegistry
  issuers: IssuerRegistry
  store: JsonChainStore
  state: NodeState
  resolvers: ResolverHolder
  validator: ChainValidator
  validity_cache: ValidityCache
  peers: PeerRegistry
  mempool: Mempool
  documents: DocumentIndex  # finalized hashes -> chain positions
  forwarding: ForwardService
  primary_status: PrimaryStatusProvider
  submission_lock: asyncio.Lock
  inflight: set[str]  # hashes being forwarded by this (non-primary) node
  metrics: MetricsRecorder
  gateway: ValidationGateway
  chain_state: ChainState  # the only owner of the live chain (UC-17)

  def current_blocks(self) -> tuple[Block, ...]:
    """A consistent view of the live chain (the stored copy while it is invalid)."""
    return self.chain_state.blocks


def _same_key(a: PublicKey, b: PublicKey) -> bool:
  return public_key_to_pem(a) == public_key_to_pem(b)


def _cross_check_keys(
  config: NodeConfig, validators: ValidatorRegistry, issuers: IssuerRegistry, state: NodeState
) -> None:
  node_entry = active_entry(validators.entries, config.node_id)
  if node_entry is None:
    raise BootError(f"NODE_ID {config.node_id!r} has no active entry in the ValidatorSet")
  if not _same_key(node_entry.public_key, state.node_key.public_key):
    raise BootError(f"node key store does not match the ValidatorSet entry of {config.node_id!r}")
  issuer_entry = active_entry(issuers.entries, config.issuer_id)
  if issuer_entry is None:
    raise BootError(f"ISSUER_ID {config.issuer_id!r} has no active entry in the IssuerRegistry")
  if not _same_key(issuer_entry.public_key, state.issuer_key.public_key):
    raise BootError(
      f"issuer key store does not match the IssuerRegistry entry of {config.issuer_id!r}"
    )


def build_node_context(
  config: NodeConfig,
  *,
  forwarder: RecordForwarder | None = None,
  primary_status: PrimaryStatusProvider | None = None,
) -> NodeContext:
  validators = load_validator_registry(config.validators_path)
  issuers = load_issuer_registry(config.issuers_path)
  logger.info(
    "ValidatorSet loaded: n=%d f=%d members=%s",
    validators.n,
    validators.f,
    sorted({e.identity for e in validators.entries}),
  )
  logger.info("IssuerRegistry loaded: issuer_ids=%s", sorted({e.identity for e in issuers.entries}))
  is_pow = config.consensus_mode == "pow"
  resolvers = ResolverHolder(CombinedKeyResolver(validators, issuers))
  resolver = resolvers.current
  core_validator_set = None if is_pow else validators.to_core()
  store = JsonChainStore(config.chain_path)
  try:
    state = restore_node_state(
      store,
      issuer_key_path=config.issuer_key_path,
      node_key_path=config.node_key_path,
      resolve_node_key=resolver.resolve_node_key,
      resolve_issuer_key=resolver.resolve_issuer_key,
      expected_difficulty=config.expected_difficulty if is_pow else None,
      validator_set=core_validator_set,
      allow_fresh=config.init_chain,
    )
    _cross_check_keys(config, validators, issuers, state)
  except Exception:
    store.close()
    raise
  if not state.restored.valid:
    logger.error(
      "persisted chain is INVALID: first_invalid_index=%s failure_type=%s; startup sync will "
      "try to replace it with a valid peer chain",
      state.restored.validation.first_invalid_index,
      state.restored.validation.failure_type,
    )
  logger.info("node %s started in %s mode", config.node_id, config.consensus_mode)
  logger.info("effective FORWARD_ACK_TIMEOUT_MS=%d", config.forward_ack_timeout_ms)
  validator = ChainValidator(
    resolvers,
    expected_difficulty=config.expected_difficulty if is_pow else None,
    validator_set=core_validator_set,
  )
  validity_cache = ValidityCache(validator)
  validity_cache.initialize(state.restored.blocks, state.restored.validation)
  documents = DocumentIndex(state.restored.blocks)
  mempool = Mempool()
  chain_state = ChainState(
    state.restored.blocks,
    valid=state.restored.valid,
    store=store,
    validator=validator,
    validity_cache=validity_cache,
    documents=documents,
    mempool=mempool,
    requeue_dropped=is_pow,
  )
  gateway = ValidationGateway(
    validator,
    resolvers,
    lambda: chain_state.blocks,
    max_future_skew_ms=config.max_future_skew_ms,
  )
  return NodeContext(
    config=config,
    validators=validators,
    issuers=issuers,
    store=store,
    state=state,
    resolvers=resolvers,
    validator=validator,
    validity_cache=validity_cache,
    peers=PeerRegistry(config.node_id),
    mempool=mempool,
    documents=documents,
    forwarding=ForwardService(
      forwarder or UnavailableForwarder(), PendingForwards(), config.forward_ack_timeout_ms
    ),
    primary_status=primary_status or default_primary_status,
    submission_lock=asyncio.Lock(),
    inflight=set(),
    metrics=MetricsRecorder(),
    gateway=gateway,
    chain_state=chain_state,
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
  context = build_node_context(
    config, forwarder=forwarder, primary_status=primary_status
  )  # fail fast at construction, not on first request

  def lookup_key(node_id: str) -> PublicKey | None:
    # Connection identity: a ValidatorSet key, else a registered PeerInfo key. Block
    # authorship is stricter (ValidatorSet only) and is judged by the validation gateway.
    resolver = context.resolvers.current
    if node_id in resolver.known_node_ids:  # a validator id is never answered from PeerInfo
      return resolver.resolve_node_key(node_id, now_ms())
    info = next((p for p in context.peers.list() if p.node_id == node_id), None)
    return public_key_from_pem(info.public_key.encode("ascii")) if info is not None else None

  manager = PeerConnectionManager(
    self_id=config.node_id,
    node_key=context.state.node_key.private_key,
    lookup_key=lookup_key,
    peer_addresses=lambda: [(p.node_id, p.host, p.port) for p in context.peers.list()],
    known_ids=lambda: context.resolvers.current.active_node_ids,
    connector=connector or WebsocketsConnector(),
    on_message=lambda peer_id, message: dispatch(peer_id, message),
    sleep=sleep,
    **(network_options or {}),
  )
  announcements: set[asyncio.Task[None]] = set()
  engine: ConsensusEngine | None = None
  pbft_engine: PbftEngine | None = None

  def is_validator(node_id: str) -> bool:
    return node_id in context.resolvers.current.active_node_ids

  async def announce(block: Block) -> None:
    # fire and forget: one slow peer must not delay the next block
    task = asyncio.create_task(broadcast_block(manager, block))
    announcements.add(task)
    task.add_done_callback(announcements.discard)

  if mine and config.consensus_mode == "pow":  # also on an invalid chain: sync may heal it
    engine = PowEngine(context, on_block_mined=announce)
  elif mine:  # pbft: votes go to ValidatorSet members only, never to PeerInfo peers

    async def send_votes(message: dict[str, Any]) -> None:
      await manager.broadcast(message, only=context.resolvers.current.active_node_ids)

    pbft_engine = PbftEngine(
      context,
      send=send_votes,
      on_finalized=announce,  # finalized blocks also reach non-validators and lagging nodes
      flag=manager.flag,
      on_needs_sync=lambda peer_id: sync.request(peer_id),
    )
    engine = pbft_engine
  sync = ChainSync(
    state=context.chain_state,
    validator=context.validator,
    gateway=context.gateway,
    mode=config.consensus_mode,
    peers=lambda: [PeerAddress(p.node_id, p.host, p.port) for p in context.peers.list()],
    fetcher=chain_fetcher or HttpChainFetcher(),
    flag=manager.flag,
    page_size=config.max_page_size,
    expected_difficulty=config.expected_difficulty,
    # startup is confirmed only by a ValidatorSet member, never by an arbitrary PeerInfo entry
    is_validator=is_validator,
    sleep=sleep,
  )
  receiver = BlockReceiver(context.gateway, engine, manager, on_needs_sync=sync.request)
  pbft_receiver = PbftReceiver(pbft_engine, is_validator=is_validator, flag=manager.flag)

  async def dispatch(peer_id: str, message: dict[str, Any]) -> None:
    if is_pbft_message(message):
      await pbft_receiver.on_message(peer_id, message)
    else:
      await receiver.on_message(peer_id, message)

  @asynccontextmanager
  async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    task: asyncio.Task[None] | None = None
    background: set[asyncio.Task[None]] = set()
    app.state.accepting = False  # nothing is served before the startup sync (UC-3-F)

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
      payload = own_entry(context, wall_ms()).model_dump(exclude={"last_seen"})

      def accept(entry: PeerOut) -> bool:
        return (
          validator_registration_error(
            context,
            node_id=entry.node_id,
            host=entry.host,
            port=entry.port,
            public_key=entry.public_key,
            issued_at=entry.issued_at,
            signature=entry.signature,
          )
          is None
        )

      task = asyncio.create_task(
        register_with_seeds(
          config.seed_peers,
          payload,
          context.peers,
          peer_transport or UrllibTransport(),
          PeerOut,
          sleep=sleep,
          accept=accept,
        )
      )
    if config.seed_peers or len(context.peers):
      background.add(asyncio.create_task(go_live(), name="startup-sync"))  # serve 503 meanwhile
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
      for announcement in list(announcements):
        announcement.cancel()
      await manager.stop()
      if task is not None:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
      context.store.close()

  app = FastAPI(title="Document verification node", lifespan=lifespan)
  app.state.context = context
  app.state.engine = engine
  app.state.manager = manager
  app.state.receiver = receiver
  app.state.pbft_receiver = pbft_receiver
  app.state.sync = sync
  app.state.accepting = False  # the lifespan flips it once the startup sync is done
  install_error_handlers(app)
  app.include_router(node_info_router)
  app.include_router(peers_router)
  app.include_router(chain_router)
  app.include_router(documents_router)
  app.include_router(metrics_router)
  app.include_router(ws_blocks_router)
  # JSON escapes can inflate metadata up to ~3x its canonical size; 4x plus slack is safe.
  app.add_middleware(
    BodyLimitMiddleware, limits={"/documents": 4 * config.max_metadata_bytes + 1024}
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
