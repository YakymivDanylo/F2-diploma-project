"""Candidate block structure: hashed preimage, batch content, and post-hash attestations."""
from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from typing import Any, Literal

from .document_record import DocumentRecord, verify_document_record
from .hashing import sha256_of_canonical
from .keys import PrivateKey, PublicKey
from .merkle import EmptyBatchError, build_root
from .signing import sign_canonical

Algorithm = Literal["pow", "pbft", "genesis"]
ResolveIssuerKey = Callable[[str], PublicKey | None]

__all__ = [
  "Algorithm",
  "Block",
  "DuplicateDocumentHashError",
  "EmptyBatchError",
  "InvalidRecordSignatureError",
  "attach_proposer_signature",
  "build_candidate_block",
]

class InvalidRecordSignatureError(ValueError):
    """Raised when a record in the batch fails signature verification; names the offending index."""
    def __init__(self, index: int, document_hash: str) -> None:
      self.index = index
      self.document_hash = document_hash
      super().__init__(f"document record at index {index} (document_hash={document_hash!r}) "
        "failed signature verification",
      )

class DuplicateDocumentHashError(ValueError):
    """Raised when the same document_hash appears more than once in a single batch."""
    def __init__(self, document_hash: str) -> None:
        self.document_hash = document_hash
        super().__init__(f"duplicate document_hash within batch: {document_hash!r}")

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
  sealed_consensus: dict[str, Any]

  # -- batch content (never part of hashed preimage) --
  document_records: tuple[DocumentRecord, ...]

  # -- attestations, attached strictly afetr hashing --
  block_hash: str
  proposer_signature: str | None = None
  commit_signatures: tuple[str, ...] = ()

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
  resolve_issuer_key: ResolveIssuerKey,                            
) -> None:
  for index, record in enumerate(records):
    issuer_key = resolve_issuer_key(record.issuer_id)
    if issuer_key is None or not verify_document_record(record, issuer_key):
      raise InvalidRecordSignatureError(index, record.document_hash)


def _reject_duplicate_document_hashes(records: Sequence[DocumentRecord]) -> None:
  seen: set[str] = set()
  for record in records:
    if record.document_hash in seen:
      raise DuplicateDocumentHashError(record.document_hash)
    seen.add(record.document_hash)

def build_candidate_block(
  records: Sequence[DocumentRecord],
  *,
  previous_hash: str,
  index: int,
  timestamp: int,
  proposer_id: str,
  algorithm: Algorithm,
  sealed_consensus: dict[str, Any],
  resolve_issuer_key: ResolveIssuerKey,
) -> Block:
    """Build and hash a candidate block from a batch of signed records.
  
    Verifies every record's signature first (naming the offending index on failure),
    rejects an empty batch, and rejects a batch containing a repeated `document_hash`
    - never silently deduplicating. Only then computes `merkle_root` and `block_hash`
    over the canonical preimage. Never attaches `proposer_signature` -
    see `attach_proposer_signature`.
    """
    if not records:
      raise EmptyBatchError("cannot build a candidate block from zero document records")
    _verify_batch_signatures(records, resolve_issuer_key)
    _reject_duplicate_document_hashes(records)
  
    merkle_root = build_root(records)
    preimage: dict[str, Any] = {
      "index": index,
      "timestamp": timestamp,
      "previous_hash": previous_hash,
      "merkle_root": merkle_root,
      "proposer_id": proposer_id,
      "algorithm": algorithm,
      "sealed_consensus": sealed_consensus,
    }
    block_hash = sha256_of_canonical(preimage)
  
    return Block(
      index=index,
      timestamp=timestamp,
      previous_hash=previous_hash,
      merkle_root=merkle_root,
      proposer_id=proposer_id,
      algorithm=algorithm,
      sealed_consensus=sealed_consensus,
      document_records=tuple(records),
      block_hash=block_hash,
    )

def attach_proposer_signature(block: Block, node_private_key: PrivateKey) -> Block:
  """Sign the block's canonical preimage with the proposer's NodeKeyPair - a post-hash step."""
  proposer_signature = sign_canonical(node_private_key, block.preimage_dict())
  return replace(block, proposer_signature=proposer_signature)