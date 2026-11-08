"""App factory and boot sequence.

Boot order: load registries (fail fast) -> open chain store -> reload keys + validated
chain (missing chain fails closed unless INIT_CHAIN) -> cross-check key stores against the
registries -> serve. Exactly one of expected_difficulty (pow) / ValidatorSet (pbft) is
passed to the core, per CONSENSUS_MODE.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from blockchain_core import (
  Block,
  JsonChainStore,
  NodeState,
  public_key_to_pem,
  restore_node_state,
)
from blockchain_core.keys import PublicKey
from node.api.chain import router as chain_router
from node.api.documents import router as documents_router
from node.api.metrics import router as metrics_router
from node.api.node_info import router as node_info_router
from node.api.peers import PeerOut
from node.api.peers import router as peers_router
from node.body_limit import BodyLimitMiddleware
from node.config import NodeConfig, load_config
from node.consensus.base import ConsensusEngine
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
from node.peers.registry import PeerRegistry
from node.peers.seed_registration import PeerTransport, UrllibTransport, register_with_seeds
from node.registries import (
  IssuerRegistry,
  ValidatorRegistry,
  active_entry,
  load_issuer_registry,
  load_validator_registry,
)
from node.validity_cache import ChainValidator, ValidityCache

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

  def current_blocks(self) -> tuple[Block, ...]:
    """The live chain (grows as blocks are appended); the stored copy if it is unextendable."""
    chain = self.state.restored.chain
    return chain.blocks if chain is not None else self.state.restored.blocks


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
    logger.error("persisted chain is INVALID: %s", state.restored.validation)
  logger.info("node %s started in %s mode", config.node_id, config.consensus_mode)
  logger.info("effective FORWARD_ACK_TIMEOUT_MS=%d", config.forward_ack_timeout_ms)
  validator = ChainValidator(
    resolvers,
    expected_difficulty=config.expected_difficulty if is_pow else None,
    validator_set=core_validator_set,
  )
  validity_cache = ValidityCache(validator)
  validity_cache.initialize(state.restored.blocks, state.restored.validation)
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
    mempool=Mempool(),
    documents=DocumentIndex(state.restored.blocks),
    forwarding=ForwardService(
      forwarder or UnavailableForwarder(), PendingForwards(), config.forward_ack_timeout_ms
    ),
    primary_status=primary_status or default_primary_status,
    submission_lock=asyncio.Lock(),
    inflight=set(),
    metrics=MetricsRecorder(),
  )


def create_app(
  config: NodeConfig,
  *,
  peer_transport: PeerTransport | None = None,
  sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
  forwarder: RecordForwarder | None = None,
  primary_status: PrimaryStatusProvider | None = None,
  mine: bool = True,
) -> FastAPI:
  context = build_node_context(
    config, forwarder=forwarder, primary_status=primary_status
  )  # fail fast at construction, not on first request

  engine: ConsensusEngine | None = None
  if mine and config.consensus_mode == "pow" and context.state.restored.chain is not None:
    engine = PowEngine(context)

  @asynccontextmanager
  async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    task: asyncio.Task[None] | None = None
    if engine is not None:
      await engine.start()
    if config.seed_peers:
      payload = {
        "node_id": config.node_id,
        "host": config.node_host,
        "port": config.node_port,
        "public_key": public_key_to_pem(context.state.node_key.public_key).decode("ascii"),
      }
      task = asyncio.create_task(
        register_with_seeds(
          config.seed_peers,
          payload,
          context.peers,
          peer_transport or UrllibTransport(),
          PeerOut,
          sleep=sleep,
        )
      )
    try:
      yield
    finally:
      app.state.accepting = False
      if engine is not None:
        await engine.stop()
      if task is not None:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
      context.store.close()

  app = FastAPI(title="Document verification node", lifespan=lifespan)
  app.state.context = context
  app.state.engine = engine
  app.state.accepting = True  # Slice 16b holds this False until startup sync completes
  install_error_handlers(app)
  app.include_router(node_info_router)
  app.include_router(peers_router)
  app.include_router(chain_router)
  app.include_router(documents_router)
  app.include_router(metrics_router)
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
