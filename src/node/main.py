"""App factory and boot sequence.

Boot order: load registries (fail fast) -> open chain store -> reload keys + validated
chain (missing chain fails closed unless INIT_CHAIN) -> cross-check key stores against the
registries -> serve. Exactly one of expected_difficulty (pow) / ValidatorSet (pbft) is
passed to the core, per CONSENSUS_MODE.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from blockchain_core import JsonChainStore, NodeState, public_key_to_pem, restore_node_state
from blockchain_core.keys import KeyResolver, PublicKey
from node.config import NodeConfig, load_config
from node.errors import install_error_handlers
from node.registries import (
  IssuerRegistry,
  KeyEntry,
  ValidatorRegistry,
  active_entry,
  load_issuer_registry,
  load_validator_registry,
)

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


def _current_key_resolver(entries: tuple[KeyEntry, ...]) -> KeyResolver:
  """Interim resolver: the active key regardless of timestamp (Slice 11 makes it time-aware)."""
  keys = {e.identity: e.public_key for e in entries if e.retired_at is None}

  def resolve(identity: str, at_timestamp: int) -> PublicKey | None:
    return keys.get(identity)

  return resolve


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


def build_node_context(config: NodeConfig) -> NodeContext:
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
  store = JsonChainStore(config.chain_path)
  try:
    state = restore_node_state(
      store,
      issuer_key_path=config.issuer_key_path,
      node_key_path=config.node_key_path,
      resolve_node_key=_current_key_resolver(validators.entries),
      resolve_issuer_key=_current_key_resolver(issuers.entries),
      expected_difficulty=config.expected_difficulty if is_pow else None,
      validator_set=None if is_pow else validators.to_core(),
      allow_fresh=config.init_chain,
    )
    _cross_check_keys(config, validators, issuers, state)
  except Exception:
    store.close()
    raise
  if not state.restored.valid:
    logger.error("persisted chain is INVALID: %s", state.restored.validation)
  logger.info("node %s started in %s mode", config.node_id, config.consensus_mode)
  return NodeContext(
    config=config, validators=validators, issuers=issuers, store=store, state=state
  )


def create_app(config: NodeConfig) -> FastAPI:
  context = build_node_context(config)  # fail fast at construction, not on first request

  @asynccontextmanager
  async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    yield
    context.store.close()

  app = FastAPI(title="Document verification node", lifespan=lifespan)
  app.state.context = context
  install_error_handlers(app)
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
