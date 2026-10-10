"""Chain validation: core checklist with injected, time-aware key resolvers.

Performs no registry lookup and no network call - every key is obtained through a
caller-supplied resolver. This is the single checklist reused by proposal-time,
sync-time, and cache-refresh callers, in full (`validate_chain`) or incrementally
(`validate_extension`) - both run exactly the same per-block checks.

The functions are total over hostile input: a malformed or tampered block yields a
failed `ValidationResult`, never an exception. The one deliberate exception is a
zero-length chain, which is not a validatable input at all.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from .block import Block
from .canonical import CanonicalizationError
from .document_record import DocumentRecord, verify_document_record
from .genesis import GENESIS_BLOCK_HASH, build_genesis_block
from .hashing import sha256_of_canonical
from .keys import KeyResolver, PublicKey
from .merkle import EmptyBatchError, build_root
from .signing import verify_canonical

FailureType = Literal["hash", "link", "merkle", "signature", "structural"]

__all__ = [
  "FailureType",
  "InvalidChainInputError",
  "KeyResolver",
  "ValidationResult",
  "validate_chain",
  "validate_extension",
]


class InvalidChainInputError(ValueError):
  """Raised when the input is not a validatable chain (e.g. zero blocks)."""


@dataclass(frozen=True)
class ValidationResult:
  valid: bool
  first_invalid_index: int | None = None
  failure_type: FailureType | None = None

  def __post_init__(self) -> None:
    if self.valid != (self.failure_type is None and self.first_invalid_index is None):
      raise ValueError("a result is valid iff it has no failure_type and no first_invalid_index")


_VALID = ValidationResult(valid=True)


def _fail(index: int, failure_type: FailureType) -> ValidationResult:
  return ValidationResult(valid=False, first_invalid_index=index, failure_type=failure_type)


def _recompute_hash(block: Block) -> str | None:
  try:
    return sha256_of_canonical(block.preimage_dict())
  except CanonicalizationError:
    return None


def _genesis_matches_constants(block: object) -> bool:
  """Full equality with the frozen genesis - preimage, hash, and every attestation/batch field."""
  expected = build_genesis_block()
  return (
    isinstance(block, Block)
    and block == expected
    and block.block_hash == GENESIS_BLOCK_HASH
    and _recompute_hash(block) == GENESIS_BLOCK_HASH
  )


def _well_formed(block: object) -> bool:
  """Type-level shape only; value mismatches are reported by the specific checks below."""
  return (
    isinstance(block, Block)
    and type(block.index) is int
    and type(block.timestamp) is int
    and isinstance(block.previous_hash, str)
    and isinstance(block.merkle_root, str)
    and isinstance(block.block_hash, str)
    and isinstance(block.proposer_id, str)
    and block.algorithm in ("pow", "pbft")
    and isinstance(block.sealed_consensus, Mapping)
    and isinstance(block.document_records, tuple)
    and all(isinstance(record, DocumentRecord) for record in block.document_records)
  )


def _merkle_ok(block: Block) -> bool:
  try:
    return build_root(block.document_records) == block.merkle_root
  except (EmptyBatchError, CanonicalizationError):
    return False


def _resolve(resolver: KeyResolver, identity: str, timestamp: int) -> PublicKey | None:
  """A resolver that raises is treated exactly like NOT_FOUND: fail closed."""
  try:
    return resolver(identity, timestamp)
  except Exception:
    return None


def _signatures_ok(
  block: Block,
  resolve_node_key: KeyResolver,
  resolve_issuer_key: KeyResolver,
) -> bool:
  if not block.proposer_id or not block.proposer_signature:
    return False
  node_key = _resolve(resolve_node_key, block.proposer_id, block.timestamp)
  if node_key is None:
    return False
  if not verify_canonical(node_key, block.preimage_dict(), block.proposer_signature):
    return False
  for record in block.document_records:
    issuer_key = _resolve(resolve_issuer_key, record.issuer_id, block.timestamp)
    if issuer_key is None or not verify_document_record(record, issuer_key):
      return False
  return True


def _structure_ok(block: Block, previous: Block) -> bool:
  hashes = [record.document_hash for record in block.document_records]
  return (
    block.index == previous.index + 1
    and block.timestamp >= previous.timestamp
    and len(set(hashes)) == len(hashes)
  )


def _check_consensus(
  block: Block,
  expected_difficulty: int | None,
  validator_set: object | None,
) -> None:
  """Hook for Slice 7 (PoW difficulty / PBFT quorum); reached only if the caller opts in.

  Slice 7 replaces this with real checks and makes the parameters mandatory for the
  matching algorithm, so that omitting them can no longer skip consensus verification.
  """
  if block.algorithm == "pow" and expected_difficulty is not None:
    raise NotImplementedError("PoW difficulty check is implemented in Slice 7")
  if block.algorithm == "pbft" and validator_set is not None:
    raise NotImplementedError("PBFT quorum check is implemented in Slice 7")


def _validate_block(
  block: Block,
  previous: Block,
  previous_hash: str,
  *,
  resolve_node_key: KeyResolver,
  resolve_issuer_key: KeyResolver,
  expected_difficulty: int | None,
  validator_set: object | None,
) -> tuple[FailureType | None, str]:
  """The per-block checklist; returns (failure_type or None, this block's recomputed hash)."""
  if not _well_formed(block):
    return "structural", ""
  recomputed = _recompute_hash(block)
  if recomputed is None or recomputed != block.block_hash:
    return "hash", ""
  if block.previous_hash != previous_hash:
    return "link", recomputed
  if not _merkle_ok(block):
    return "merkle", recomputed
  if not _signatures_ok(block, resolve_node_key, resolve_issuer_key):
    return "signature", recomputed
  if not _structure_ok(block, previous):
    return "structural", recomputed
  _check_consensus(block, expected_difficulty, validator_set)
  return None, recomputed


def _validate_run(
  blocks: Sequence[Block],
  previous: Block,
  previous_hash: str,
  start_position: int,
  *,
  resolve_node_key: KeyResolver,
  resolve_issuer_key: KeyResolver,
  expected_difficulty: int | None,
  validator_set: object | None,
) -> ValidationResult:
  for position, block in enumerate(blocks, start=start_position):
    failure, recomputed = _validate_block(
      block,
      previous,
      previous_hash,
      resolve_node_key=resolve_node_key,
      resolve_issuer_key=resolve_issuer_key,
      expected_difficulty=expected_difficulty,
      validator_set=validator_set,
    )
    if failure is not None:
      return _fail(position, failure)
    previous, previous_hash = block, recomputed
  return _VALID


def validate_chain(
  blocks: Sequence[Block],
  *,
  resolve_node_key: KeyResolver,
  resolve_issuer_key: KeyResolver,
  expected_difficulty: int | None = None,
  validator_set: object | None = None,
) -> ValidationResult:
  """Validate `blocks` front to back and report the earliest failing block.

  Per non-genesis block, in order: `"hash"`, `"link"`, `"merkle"`, `"signature"`
  (proposer and every document record), `"structural"` (index, timestamp, duplicate
  `document_hash` within the block). A block whose fields have the wrong types, or an
  `algorithm` other than pow/pbft, is `"structural"`. Genesis must equal the frozen
  genesis block exactly (any difference is `"hash"` at position 0). Unknown identities
  and resolvers that raise fail closed as `"signature"`.

  `first_invalid_index` is the block's position in `blocks`, not its (possibly
  tampered) `index` field. Single pass, each block hashed once - O(n).

  Not checked here (node-layer policy, Epic 3): `document_hash` uniqueness across
  blocks, and bounding `timestamp` against wall-clock time or key-revocation times.
  """
  if not blocks:
    raise InvalidChainInputError("cannot validate a chain of zero blocks")
  genesis = blocks[0]
  if not _genesis_matches_constants(genesis):
    return _fail(0, "hash")
  return _validate_run(
    blocks[1:],
    genesis,
    genesis.block_hash,
    1,
    resolve_node_key=resolve_node_key,
    resolve_issuer_key=resolve_issuer_key,
    expected_difficulty=expected_difficulty,
    validator_set=validator_set,
  )


def validate_extension(
  trusted_tip: Block,
  new_blocks: Sequence[Block],
  *,
  resolve_node_key: KeyResolver,
  resolve_issuer_key: KeyResolver,
  expected_difficulty: int | None = None,
  validator_set: object | None = None,
) -> ValidationResult:
  """Validate only `new_blocks` appended after an already-validated `trusted_tip`.

  Runs the identical per-block checklist as `validate_chain`, so for a simple
  extension the result matches a full validation of `chain + new_blocks`.
  `first_invalid_index` is `trusted_tip.index + 1 + offset`. The tip is trusted, not
  re-verified: callers must only pass a tip they validated earlier. No new blocks is
  trivially valid.
  """
  return _validate_run(
    new_blocks,
    trusted_tip,
    trusted_tip.block_hash,
    trusted_tip.index + 1,
    resolve_node_key=resolve_node_key,
    resolve_issuer_key=resolve_issuer_key,
    expected_difficulty=expected_difficulty,
    validator_set=validator_set,
  )
