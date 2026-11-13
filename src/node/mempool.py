"""Pending records (mempool) and the index of finalized document hashes.

Only a node that is the primary (or any PoW node) places records in its mempool; a
non-primary never does (FR-22 (x)). The index maps a document hash to the chain positions
where it appears, so duplicate checks and lookups do not scan the chain per request. More
than one position for a hash is a data-integrity problem, surfaced by the lookup endpoint.
"""

from __future__ import annotations

from collections.abc import Sequence

from blockchain_core import Block, DocumentRecord


class Mempool:
  def __init__(self) -> None:
    self._records: dict[str, DocumentRecord] = {}

  def contains(self, document_hash: str) -> bool:
    return document_hash in self._records

  def add(self, record: DocumentRecord) -> None:
    if record.document_hash in self._records:
      raise ValueError("document_hash already pending")
    self._records[record.document_hash] = record

  def snapshot(self) -> list[DocumentRecord]:
    """Pending records in arrival order (the consensus engines batch from this)."""
    return list(self._records.values())

  def remove(self, document_hashes: Sequence[str]) -> None:
    for document_hash in document_hashes:
      self._records.pop(document_hash, None)

  def __len__(self) -> int:
    return len(self._records)


class DocumentIndex:
  def __init__(self, blocks: Sequence[Block] = ()) -> None:
    self._where: dict[str, list[int]] = {}
    self.reset(blocks)

  def reset(self, blocks: Sequence[Block]) -> None:
    """Rebuild the index for a whole (replaced) chain."""
    where: dict[str, list[int]] = {}
    for position, block in enumerate(blocks):
      for document_hash in {record.document_hash for record in block.document_records}:
        where.setdefault(document_hash, []).append(position)
    self._where = where

  def add_block(self, block: Block, position: int) -> None:
    """`position` is the block's place in the chain list (not its self-declared index)."""
    for document_hash in {record.document_hash for record in block.document_records}:
      self._where.setdefault(document_hash, []).append(position)

  def block_indexes(self, document_hash: str) -> list[int]:
    return list(self._where.get(document_hash, ()))

  def contains(self, document_hash: str) -> bool:
    return document_hash in self._where
