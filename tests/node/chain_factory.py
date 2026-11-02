"""Build valid PoW / PBFT chains signed with the keys of a `node_env`."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from node_helpers import NodeEnv

from blockchain_core import (
  Block,
  JsonChainStore,
  attach_proposer_signature,
  build_candidate_block,
  build_genesis_block,
  create_document_record,
  sha256_hex,
  sha256_of_canonical,
  sign_commit,
)
from blockchain_core.validation import pow_target

BASE_TS = 1_700_000_001_000
STEP = 1_000


def _record(env: NodeEnv, seed: int):
  return create_document_record(
    document_hash=sha256_hex(f"document-{seed}".encode()),
    issuer_id="issuer1",
    issued_at=1_700_000_000_000 + seed,
    metadata={"seed": seed},
    issuer_private_key=env.issuer_key.private_key,
  )


def _candidate(env: NodeEnv, previous: Block, seed: int, algorithm, sealed, proposer="node1"):
  def resolve_issuer(issuer_id: str, at_timestamp: int):
    return env.issuer_key.public_key if issuer_id == "issuer1" else None

  return build_candidate_block(
    [_record(env, seed)],
    previous_hash=previous.block_hash,
    index=previous.index + 1,
    timestamp=BASE_TS + (previous.index + 1) * STEP,
    proposer_id=proposer,
    algorithm=algorithm,
    sealed_consensus=sealed,
    resolve_issuer_key=resolve_issuer,
  )


def pow_block(env: NodeEnv, previous: Block, seed: int, *, difficulty: int = 1, proposer="node1"):
  block = _candidate(env, previous, seed, "pow", {"nonce": 0, "difficulty": difficulty}, proposer)
  target = pow_target(difficulty)
  nonce = 0
  while int(block.block_hash, 16) >= target:
    nonce += 1
    changed = replace(block, sealed_consensus={"nonce": nonce, "difficulty": difficulty})
    block = replace(changed, block_hash=sha256_of_canonical(changed.preimage_dict()))
  return attach_proposer_signature(block, env.node_key.private_key)


def pow_chain(env: NodeEnv, length: int, *, difficulty: int = 1, proposer="node1") -> list[Block]:
  blocks = [build_genesis_block()]
  for seed in range(1, length + 1):
    blocks.append(pow_block(env, blocks[-1], seed, difficulty=difficulty, proposer=proposer))
  return blocks


def pbft_block(env: NodeEnv, previous: Block, seed: int, *, signers: int = 3) -> Block:
  block = attach_proposer_signature(
    _candidate(env, previous, seed, "pbft", {"view_number": 0}), env.node_key.private_key
  )
  commits = tuple(
    sign_commit(block, node_id, env.validator_keys[node_id])
    for node_id in list(env.validator_keys)[:signers]
  )
  return replace(block, commit_signatures=commits)


def pbft_chain(env: NodeEnv, length: int, *, signers: int = 3) -> list[Block]:
  blocks = [build_genesis_block()]
  for seed in range(1, length + 1):
    blocks.append(pbft_block(env, blocks[-1], seed, signers=signers))
  return blocks


def save_chain(env: NodeEnv, blocks: list[Block]) -> None:
  store = JsonChainStore(Path(env.env["CHAIN_PATH"]))
  try:
    store.save(blocks)
  finally:
    store.close()
