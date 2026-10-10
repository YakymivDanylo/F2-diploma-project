"""Candidate block structure: hashed preimage, batch content, and post-hash attestations."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any, Literal

from .canonical import deep_freeze
from .document_record import DocumentRecord, verify_document_record
from .hashing import HEX64_RE, sha256_of_canonical
from .keys import KeyPair, KeyResolver, NodeKeyPair, PrivateKey, resolve_signing_key
from .merkle import EmptyBatchError, build_root
from .signing import sign_canonical

Algorithm = Literal["pow", "pbft", "genesis"]

__all__ = [
  "Algorithm",
  "Block",
  "DuplicateDocumentHashError",
  "EmptyBatchError",
  "InvalidBlockParametersError",
  "InvalidRecordSignatureError",
  "attach_proposer_signature",
  "build_candidate_block",
]


class InvalidRecordSignatureError(ValueError):
  """Raised when a record in the batch fails signature verification; names the offending index."""

  def __init__(self, index: int, document_hash: str) -> None:
    self.index = index
    self.document_hash = document_hash
    super().__init__(
      f"document record at index {index} (document_hash={document_hash!r}) "
      "failed signature verification",
    )


class DuplicateDocumentHashError(ValueError):
  """Raised when the same document_hash appears more than once in a single batch."""

  def __init__(self, document_hash: str) -> None:
    self.document_hash = document_hash
    super().__init__(f"duplicate document_hash within batch: {document_hash!r}")


class InvalidBlockParametersError(ValueError):
  """Raised when build_candidate_block is given parameters no real block may have."""


@dataclass(frozen=True)
class Block:
  """A candidate or finalized block, with its three field groups kept explicitly separate.

  Hashed preimage (`index` .. `sealed_consensus`) is exactly what `block_hash` covers.
  `document_records` is batch content, stored for retrieval but never hashed into
  `block_hash` - its integrity is covered exclusively via `merkle_root`. `block_hash`,
  `proposer_signature`, and `commit_signatures` are attestations attached strictly
  after hashing and are themselves never part of the hashed bytes.
  """

  # -- hashed preimage --
  index: int
  timestamp: int
  previous_hash: str
  merkle_root: str
  proposer_id: str | None
  algorithm: Algorithm
  sealed_consensus: Mapping[str, Any]

  # -- batch content (never part of hashed preimage) --
  document_records: tuple[DocumentRecord, ...]

  # -- attestations, attached strictly after hashing --
  block_hash: str
  proposer_signature: str | None = None
  commit_signatures: tuple[str, ...] = ()

  def __post_init__(self) -> None:
    # Detach from the caller's dict and make it read-only: block_hash covers it.
    object.__setattr__(self, "sealed_consensus", deep_freeze(self.sealed_consensus))

  def preimage_dict(self) -> dict[str, Any]:
    """Canonical field set covered by `block_hash` - excludes records and every attestation."""
    return {
      "index": self.index,
      "timestamp": self.timestamp,
      "previous_hash": self.previous_hash,
      "merkle_root": self.merkle_root,
      "proposer_id": self.proposer_id,
      "algorithm": self.algorithm,
      "sealed_consensus": self.sealed_consensus,
    }


def _verify_batch_signatures(
  records: Sequence[DocumentRecord],
  timestamp: int,
  resolve_issuer_key: KeyResolver,
) -> None:
  for index, record in enumerate(records):
    issuer_key = resolve_issuer_key(record.issuer_id, timestamp)
    if issuer_key is None or not verify_document_record(record, issuer_key):
      raise InvalidRecordSignatureError(index, record.document_hash)


def _reject_duplicate_document_hashes(records: Sequence[DocumentRecord]) -> None:
  seen: set[str] = set()
  for record in records:
    if record.document_hash in seen:
      raise DuplicateDocumentHashError(record.document_hash)
    seen.add(record.document_hash)


def _check_parameters(
  previous_hash: str,
  index: int,
  proposer_id: str,
  algorithm: str,
) -> None:
  if algorithm not in ("pow", "pbft"):
    raise InvalidBlockParametersError(
      f"algorithm must be 'pow' or 'pbft' ('genesis' is reserved), got {algorithm!r}"
    )
  if type(index) is not int or index < 1:
    raise InvalidBlockParametersError(f"index must be an integer >= 1, got {index!r}")
  if not HEX64_RE.fullmatch(previous_hash):
    raise InvalidBlockParametersError("previous_hash must be 64 lowercase hex characters")
  if not proposer_id:
    raise InvalidBlockParametersError("proposer_id is required")


def build_candidate_block(
  records: Sequence[DocumentRecord],
  *,
  previous_hash: str,
  index: int,
  timestamp: int,
  proposer_id: str,
  algorithm: Algorithm,
  sealed_consensus: Mapping[str, Any],
  resolve_issuer_key: KeyResolver,
) -> Block:
  """Build and hash a candidate block from a batch of signed records.

  Verifies every record's signature first - against the issuer key valid at `timestamp`,
  exactly as `validate_chain` will - naming the offending index on failure. Rejects an
  empty batch and a batch containing a repeated `document_hash`, never silently
  deduplicating. Only then computes `merkle_root` and `block_hash` over the canonical
  preimage. Never attaches `proposer_signature` - see `attach_proposer_signature`.
  """
  _check_parameters(previous_hash, index, proposer_id, algorithm)
  if not records:
    raise EmptyBatchError("cannot build a candidate block from zero document records")
  _verify_batch_signatures(records, timestamp, resolve_issuer_key)
  _reject_duplicate_document_hashes(records)

  block = Block(
    index=index,
    timestamp=timestamp,
    previous_hash=previous_hash,
    merkle_root=build_root(records),
    proposer_id=proposer_id,
    algorithm=algorithm,
    sealed_consensus=sealed_consensus,
    document_records=tuple(records),
    block_hash="",
  )
  return replace(block, block_hash=sha256_of_canonical(block.preimage_dict()))


def attach_proposer_signature(block: Block, node_private_key: PrivateKey | KeyPair) -> Block:
  """Sign the block's canonical preimage with the proposer's node key - a post-hash step.

  An `IssuerKeyPair` is refused; a bare private key is accepted.
  """
  signing_key = resolve_signing_key(node_private_key, NodeKeyPair)
  proposer_signature = sign_canonical(signing_key, block.preimage_dict())
  return replace(block, proposer_signature=proposer_signature)
