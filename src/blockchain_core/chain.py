"""In-memory hash chain: genesis-seeded, atomic check-and-append linking."""
from __future__ import annotations

import threading

from .block import Block
from .genesis import build_genesis_block

__all__ = [
  "Chain",
  "NonSequentialIndexError",
  "StalePreviousHashError",
]


class StalePreviousHashError(ValueError):
  """Raised when a candidate's previous_hash no longer matches the current tip."""

class NonSequentialIndexError(ValueError):
  """Raised when a candidate's index is not exactly tip.index + 1 (skip or duplicate)."""


class Chain:
  """Never empty - genesis exists from construction. `append` is atomic check-and-append."""

  def __init__(self) -> None:
    self._lock = threading.Lock()
    self._blocks: list[Block] = [build_genesis_block()]

  def __len__(self) -> int:
    return len(self._blocks)

  @property
  def tip(self) -> Block:
    return self._blocks[-1]

  @property
  def blocks(self) -> tuple[Block, ...]:
    return tuple(self._blocks)

  def append(self, candidate: Block) -> None:
    """Verify previous_hash/index against the current tip and append, atomically.

    Concurrent callers racing for the same next index: exactly one holds the lock
    first, appends, and moves the tip; the other's check then fails against the
    new tip and it is rejected - never both appended, never a lost update.
    """
    with self._lock:
      tip = self._blocks[-1]
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
