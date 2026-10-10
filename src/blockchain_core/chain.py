"""In-memory hash chain: genesis-seeded, atomic check-and-append linking."""
from __future__ import annotations

import threading

from .block import Block
from .genesis import build_genesis_block
from .hashing import sha256_of_canonical

__all__ = [
  "Chain",
  "InvalidBlockHashError",
  "NonSequentialIndexError",
  "StalePreviousHashError",
]


class StalePreviousHashError(ValueError):
  """Raised when a candidate's previous_hash no longer matches the current tip."""

class NonSequentialIndexError(ValueError):
  """Raised when a candidate's index is not exactly tip.index + 1 (skip or duplicate)."""

class InvalidBlockHashError(ValueError):
  """Raised when a candidate's block_hash is not the hash of its own preimage, or it is genesis."""


class Chain:
  """Never empty - genesis exists from construction. `append` is atomic check-and-append.

  `append` guards the structure the next link depends on (self-consistent `block_hash`,
  `previous_hash`, `index`); signatures, Merkle roots and consensus proofs are the job of
  `validate_chain`, which callers run on a candidate before appending it.
  """

  def __init__(self) -> None:
    self._lock = threading.Lock()
    self._blocks: list[Block] = [build_genesis_block()]

  def __len__(self) -> int:
    with self._lock:
      return len(self._blocks)

  @property
  def tip(self) -> Block:
    with self._lock:
      return self._blocks[-1]

  @property
  def blocks(self) -> tuple[Block, ...]:
    with self._lock:
      return tuple(self._blocks)

  def append(self, candidate: Block) -> None:
    """Verify hash/previous_hash/index against the current tip and append, atomically.

    Concurrent callers racing for the same next index: exactly one holds the lock
    first, appends, and moves the tip; the other's check then fails against the
    new tip and it is rejected - never both appended, never a lost update.
    """
    with self._lock:
      tip = self._blocks[-1]
      if candidate.algorithm == "genesis":
        raise InvalidBlockHashError("a second genesis block cannot be appended")
      if sha256_of_canonical(candidate.preimage_dict()) != candidate.block_hash:
        raise InvalidBlockHashError(
          "candidate.block_hash does not match the hash of its own preimage")
      if candidate.previous_hash != tip.block_hash:
        raise StalePreviousHashError(
          f"candidate.previous_hash={candidate.previous_hash!r} does not match "
          f"current tip.block_hash={tip.block_hash!r}",
        )
      if candidate.index != tip.index + 1:
        raise NonSequentialIndexError(
          f"candidate.index={candidate.index} is not tip.index + 1 ({tip.index + 1})",
        )
      self._blocks.append(candidate)
