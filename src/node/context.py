"""The node context and its boot sequence (registries -> stores -> keys -> validated chain).

`build_node_context` fails fast: unusable registries, key stores that disagree with them,
own keys that are not in force now, insecure or shared key material all raise before the
node can serve, and the chain store is closed on every failure path.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from blockchain_core import (
  Block,
  JsonChainStore,
  NodeState,
  ValidationResult,
  public_key_to_pem,
  restore_node_state,
)
from blockchain_core.keys import PublicKey
from blockchain_core.storage.chain_store import SharedKeyMaterialError
from blockchain_core.storage.key_store import KeyStoreInsecureError
from node.chain_state import ChainState
from node.config import NodeConfig
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
from node.network.connection_manager import now_ms as wall_ms
from node.peers.registry import PeerRegistry
from node.registries import (
  IssuerRegistry,
  ValidatorRegistry,
  active_entry,
  load_issuer_registry,
  load_validator_registry,
)
from node.validation_gateway import ChainValidator, ValidationGateway
from node.validity_cache import ValidityCache

logger = logging.getLogger("node")


class BootError(RuntimeError):
  """Key stores and registries disagree (or key material is unusable); the node must not
  start."""


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


def _check_keys_in_force(
  config: NodeConfig, resolver: CombinedKeyResolver, state: NodeState, at_ms: int
) -> None:
  """Own keys must be the keys the registries put in force NOW: a key whose `valid_from` is
  still in the future would sign blocks / records every peer rejects."""
  node_key = resolver.resolve_node_key(config.node_id, at_ms)
  if node_key is None or not _same_key(node_key, state.node_key.public_key):
    raise BootError(
      f"the node key of {config.node_id!r} is not in force now in the ValidatorSet "
      "(a future valid_from, or another key is in force); refusing to start"
    )
  issuer_key = resolver.resolve_issuer_key(config.issuer_id, at_ms)
  if issuer_key is None or not _same_key(issuer_key, state.issuer_key.public_key):
    raise BootError(
      f"the issuer key of {config.issuer_id!r} is not in force now in the IssuerRegistry "
      "(a future valid_from, or another key is in force); refusing to start"
    )


def _apply_future_cap(
  gateway: ValidationGateway, blocks: Sequence[Block], validation: ValidationResult
) -> ValidationResult:
  """Boot applies the same future-timestamp cap as sync and the broadcast path: a persisted
  block stamped beyond the skew window makes the chain invalid at that index (the earliest
  failure wins), so the startup sync replaces it like any other invalid chain."""
  future = gateway.first_future_block(blocks)
  if future is None:
    return validation
  if validation.valid or (
    validation.first_invalid_index is not None and future < validation.first_invalid_index
  ):
    return ValidationResult(
      valid=False, first_invalid_index=future, failure_type="timestamp_in_future"
    )
  return validation


def _revoked_signers(
  validators: ValidatorRegistry,
  issuers: IssuerRegistry,
  blocks: Sequence[Block],
  first_invalid_index: int | None,
) -> list[str]:
  """Identities with a REVOKED registry entry that signed the chain at or before the first
  invalid block: as proposer or commit signer (ValidatorSet) or as record issuer
  (IssuerRegistry). A revoked key never resolves, so history it signed turns invalid."""
  revoked_nodes = {e.identity for e in validators.entries if e.revoked}
  revoked_issuers = {e.identity for e in issuers.entries if e.revoked}
  if not revoked_nodes and not revoked_issuers:
    return []
  end = len(blocks) if first_invalid_index is None else first_invalid_index + 1
  found: set[str] = set()
  for block in blocks[:end]:
    signers = {c.node_id for c in block.commit_signatures}
    if block.proposer_id is not None:
      signers.add(block.proposer_id)
    found |= signers & revoked_nodes
    found |= {r.issuer_id for r in block.document_records} & revoked_issuers
  return sorted(found)


def _report_revoked_history(
  validators: ValidatorRegistry,
  issuers: IssuerRegistry,
  blocks: Sequence[Block],
  validation: ValidationResult,
) -> None:
  """N4: revoking a key that signed historical blocks / records makes every node's chain
  invalid at that index, so the network stops extending it. Name the cause for the operator."""
  for identity in _revoked_signers(validators, issuers, blocks, validation.first_invalid_index):
    logger.error(
      "the persisted chain is invalid at index %s and the registries REVOKE a key of %r, which "
      "signed blocks or records at or before that index: revocation invalidates history signed "
      "by that key: roll back or re-issue the chain; see docs (key revocation runbook)",
      validation.first_invalid_index,
      identity,
    )


def build_node_context(
  config: NodeConfig,
  *,
  forwarder: RecordForwarder | None = None,
  primary_status: PrimaryStatusProvider | None = None,
  now_ms: Callable[[], int] | None = None,
) -> NodeContext:
  """`now_ms` is the wall clock of the validation gateway (its timestamp windows); the default
  is the real clock. A test seam - the boot-time key checks always use the real clock."""
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
    except KeyStoreInsecureError as exc:
      raise BootError(f"key store is insecure: {exc}") from exc
    except SharedKeyMaterialError as exc:
      raise BootError(f"unusable key material: {exc}") from exc
    _cross_check_keys(config, validators, issuers, state)
    _check_keys_in_force(config, resolver, state, wall_ms())
    validator = ChainValidator(
      resolvers,
      expected_difficulty=config.expected_difficulty if is_pow else None,
      validator_set=core_validator_set,
    )
    blocks = state.restored.blocks
    # The runtime checklist (cross-block duplicate documents included), not only the core's.
    validation = validator.full(blocks)
    # the chain view is bound late: `chain_state` exists before the gateway is first queried
    gateway = ValidationGateway(
      validator,
      resolvers,
      lambda: chain_state.blocks,
      max_future_skew_ms=config.max_future_skew_ms,
      **({} if now_ms is None else {"now_ms": now_ms}),
    )
    validation = _apply_future_cap(gateway, blocks, validation)
  except Exception:
    store.close()
    raise
  if not validation.valid:
    logger.error(
      "persisted chain is INVALID: first_invalid_index=%s failure_type=%s; startup sync will "
      "try to replace it with a valid peer chain",
      validation.first_invalid_index,
      validation.failure_type,
    )
    _report_revoked_history(validators, issuers, blocks, validation)
  logger.info("node %s started in %s mode", config.node_id, config.consensus_mode)
  logger.info("effective FORWARD_ACK_TIMEOUT_MS=%d", config.forward_ack_timeout_ms)
  validity_cache = ValidityCache(validator)
  validity_cache.initialize(blocks, validation)
  documents = DocumentIndex(blocks)
  mempool = Mempool()
  chain_state = ChainState(
    blocks,
    valid=validation.valid,
    store=store,
    validator=validator,
    validity_cache=validity_cache,
    documents=documents,
    mempool=mempool,
    requeue_dropped=is_pow,
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
    # validators are never evicted from PeerInfo (TTL / full-registry eviction)
    peers=PeerRegistry(
      config.node_id, is_protected=lambda node_id: node_id in resolvers.current.known_node_ids
    ),
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
