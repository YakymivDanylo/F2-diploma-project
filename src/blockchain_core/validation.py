"""Chain validation: core checklist with injected, time-aware key resolvers.

Performs no registry lookup and no network call - every key is obtained through a
caller-supplied resolver. This is the single checklist reused by proposal-time,
sync-time, and cache-refresh callers.
"""
from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from .block import Block
from .canonical import CanonicalizationError
from .document_record import verify_document_record
from .genesis import GENESIS_BLOCK_HASH, build_genesis_block
from .hashing import sha256_of_canonical
from .keys import PublicKey
from .merkle import EmptyBatchError, build_root
from .signing import verify_canonical

FailureType = Literal["hash", "link", "merkle", "signature", "structural"]
KeyResolver = Callable[[str, int], PublicKey | None]
"""`(identity, at_timestamp) -> public key`; `None` is NOT_FOUND and fails closed."""

__all__ = [
  "FailureType",
  "InvalidChainInputError",
  "KeyResolver",
  "ValidationResult",
  "validate_chain",
]


class InvalidChainInputError(ValueError):
  """Raised when the input is not a validatable chain (e.g. zero blocks)."""


@dataclass(frozen=True)
class ValidationResult:
  valid: bool
  first_invalid_index: int | None = None
  failure_type: FailureType | None = None


_VALID = ValidationResult(valid=True)


def _fail(index: int, failure_type: FailureType) -> ValidationResult:
  return ValidationResult(valid=False, first_invalid_index=index, failure_type=failure_type)


def _recompute_hash(block: Block) -> str | None:
  try:
    return sha256_of_canonical(block.preimage_dict())
  except CanonicalizationError:
    return None


def _genesis_matches_constants(block: Block) -> bool:
  expected = build_genesis_block()
  return (
    block.preimage_dict() == expected.preimage_dict()
    and block.block_hash == GENESIS_BLOCK_HASH
    and _recompute_hash(block) == GENESIS_BLOCK_HASH
  )


def _merkle_ok(block: Block) -> bool:
  try:
    return build_root(block.document_records) == block.merkle_root
  except (EmptyBatchError, CanonicalizationError):
    return False


def _signatures_ok(block: Block, resolve_node_key: KeyResolver,
                   resolve_issuer_key: KeyResolver) -> bool:
  if block.proposer_id is None or not block.proposer_signature:
    return False
  node_key = resolve_node_key(block.proposer_id, block.timestamp)
  if node_key is None:
    return False
  try:
    if not verify_canonical(node_key, block.preimage_dict(), block.proposer_signature):
      return False
    for record in block.document_records:
      issuer_key = resolve_issuer_key(record.issuer_id, block.timestamp)
      if issuer_key is None or not verify_document_record(record, issuer_key):
        return False
  except CanonicalizationError:
    return False
  return True


def _structure_ok(block: Block, previous: Block) -> bool:
  return (
    block.index == previous.index + 1
    and block.timestamp >= previous.timestamp
    and block.algorithm != "genesis"
  )


def _check_consensus(block: Block, expected_difficulty: int | None, validator_set: Any) -> None:
  """Hook for Slice 7 (PoW difficulty / PBFT quorum); reached only if the caller opts in."""
  if block.algorithm == "pow" and expected_difficulty is not None:
    raise NotImplementedError("PoW difficulty check is implemented in Slice 7")
  if block.algorithm == "pbft" and validator_set is not None:
    raise NotImplementedError("PBFT quorum check is implemented in Slice 7")


def validate_chain(
  blocks: Sequence[Block],
  *,
  resolve_node_key: KeyResolver,
  resolve_issuer_key: KeyResolver,
  expected_difficulty: int | None = None,
  validator_set: Any = None,
) -> ValidationResult:
  """Validate `blocks` front to back and report the earliest failing block.

  Per non-genesis block, in order: `"hash"`, `"link"`, `"merkle"`, `"signature"`
  (proposer and every document record), `"structural"`. Genesis is compared only
  against the frozen constants. Unknown identities fail closed as `"signature"`.
  `first_invalid_index` is the block's position in `blocks`, not its (possibly
  tampered) `index` field. Single pass, each block hashed once - O(n).
  """
  if not blocks:
    raise InvalidChainInputError("cannot validate a chain of zero blocks")

  genesis = blocks[0]
  if not _genesis_matches_constants(genesis):
    return _fail(0, "hash")

  previous_hash = genesis.block_hash
  previous = genesis
  for position, block in enumerate(blocks[1:], start=1):
    recomputed = _recompute_hash(block)
    if recomputed is None or recomputed != block.block_hash:
      return _fail(position, "hash")
    if block.previous_hash != previous_hash:
      return _fail(position, "link")
    if not _merkle_ok(block):
      return _fail(position, "merkle")
    if not _signatures_ok(block, resolve_node_key, resolve_issuer_key):
      return _fail(position, "signature")
    if not _structure_ok(block, previous):
      return _fail(position, "structural")
    _check_consensus(block, expected_difficulty, validator_set)
    previous_hash = recomputed
    previous = block

  return _VALID
