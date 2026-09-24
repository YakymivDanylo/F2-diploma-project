from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from typing import Literal

from .canonical import canonicalize
from .document_record import DocumentRecord
from .hashing import sha256_hex

_LEAF_PREFIX = b"\x00"
_INTERNAL_PREFIX = b"\x01"
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


class EmptyBatchError(ValueError):
  """Raised when a Merkle root/proof is requested over zero document records."""

class DocumentHashNotFoundError(ValueError):
  """Raised when a proof is requested for a document_hash absent from the batch."""


@dataclass(frozen=True)
class ProofStep:
  """One level of a Merkle inclusion proof, from leaf towards the root.

  `position` names where the sibling sits relative to the node being combined:
  "left"/"right" carry `sibling_hash` for a domain-separated internal-node
  combine; "promoted" means the node had no sibling at this level (an odd
  count) and passes to the next level unchanged.
  """
  position: Literal["left", "right", "promoted"]
  sibling_hash: str | None = None

  def __post_init__(self) -> None:
    if self.position in ("left", "right"):
      if self.sibling_hash is None:
        raise ValueError(f"ProofStep position={self.position!r} requires a sibling_hash")
    elif self.position == "promoted":
      if self.sibling_hash is not None:
        raise ValueError("ProofStep position='promoted' must not carry a sibling_hash")
    else:
      raise ValueError(f"unknown ProofStep position: {self.position!r}")


def leaf_hash(record: DocumentRecord) -> str:
  """Domain-separated leaf hash: H(0x00 || canonical_bytes(record)).

  `canonical_bytes(record)` covers every `DocumentRecord` field, including
  `signature` - the leaf commits to the record as-attested, not just its
  unsigned content. `_find_index`/`build_proof` assume `document_hash` is
  unique within the batch; that uniqueness is enforced upstream (Slice 4's
  block builder, UC-2-E3), not here.
  """
  return sha256_hex(_LEAF_PREFIX + canonicalize(asdict(record)))

def _internal_hash(left: str, right: str) -> str:
  """Domain-separated internal-node hash: H(0x01 || left_hash || right_hash)."""
  return sha256_hex(_INTERNAL_PREFIX + bytes.fromhex(left) + bytes.fromhex(right))

def _build_tree_levels(leaves: list[str]) -> list[list[str]]:
  """All levels bottom-up, leaves first and the single-element root list last.

  An odd node at any level is promoted unchanged to the next level rather
  than being duplicated - this is the single place that rule is enforced,
  so `build_root` and `build_proof` can never disagree with each other.
  """
  levels = [leaves]
  current = leaves
  while len(current) > 1:
    next_level: list[str] = []
    count = len(current)
    i = 0
    while i < count:
      if i + 1 < count:
        next_level.append(_internal_hash(current[i], current[i + 1]))
        i += 2
      else:
        next_level.append(current[i])
        i += 1
    levels.append(next_level)
    current = next_level
  return levels

def _find_index(records: Sequence[DocumentRecord], document_hash: str) -> int:
  for index, record in enumerate(records):
    if record.document_hash == document_hash:
      return index
  raise DocumentHashNotFoundError(f"document_hash {document_hash!r} not found in batch")

def build_root(records: Sequence[DocumentRecord]) -> str:
  """Merkle root over `records`. N=1 degenerates to that record's leaf hash."""
  if not records:
    raise EmptyBatchError("cannot build a Merkle root over zero document records")
  leaves = [leaf_hash(record) for record in records]
  levels = _build_tree_levels(leaves)
  return levels[-1][0]

def build_proof(records: Sequence[DocumentRecord], document_hash: str) -> list[ProofStep]:
  """Sibling path from `document_hash`'s leaf up to the root. Empty for N=1."""
  if not records:
    raise EmptyBatchError("cannot build a Merkle proof over zero document records")
  index = _find_index(records, document_hash)
  leaves = [leaf_hash(record) for record in records]
  levels = _build_tree_levels(leaves)

  path: list[ProofStep] = []
  for level in levels[:-1]:
    count = len(level)
    if index % 2 == 0:
      if index + 1 < count:
        path.append(ProofStep(position="right", sibling_hash=level[index + 1]))
      else:
        path.append(ProofStep(position="promoted"))
    else:
      path.append(ProofStep(position="left", sibling_hash=level[index - 1]))
    index //= 2
  return path

def _verify_leaf_hash(current: str, proof: Sequence[ProofStep], claimed_root: str) -> bool:
  """Shared verification core. Never raises on malformed input - returns False instead,
  matching this codebase's "verification functions return bool, never raise" convention
  (see `verify_document_record`).
  """
  if not _HEX64_RE.fullmatch(current):
    return False
  for step in proof:
    if step.position == "right":
      if step.sibling_hash is None or not _HEX64_RE.fullmatch(step.sibling_hash):
        return False
      current = _internal_hash(current, step.sibling_hash)
    elif step.position == "left":
      if step.sibling_hash is None or not _HEX64_RE.fullmatch(step.sibling_hash):
        return False
      current = _internal_hash(step.sibling_hash, current)
    elif step.position == "promoted":
      continue
    else:
      return False
  return current == claimed_root

def verify_proof(record: DocumentRecord, proof: Sequence[ProofStep], claimed_root: str) -> bool:
  """Verify that `record` is included under `claimed_root`, given its inclusion proof."""
  return _verify_leaf_hash(leaf_hash(record), proof, claimed_root)

def verify_leaf_hash_proof(leaf: str, proof: Sequence[ProofStep], claimed_root: str) -> bool:
  """Verify an inclusion proof using only an already-computed leaf hash (UC-5-A) -
  no `DocumentRecord`/block object needed. The caller is responsible for `leaf`
  actually being a domain-separated leaf hash (from `leaf_hash`), not an
  arbitrary hash value - this function cannot distinguish the two.
  """
  return _verify_leaf_hash(leaf, proof, claimed_root)
