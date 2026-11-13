"""Cached chain validity behind `GET /node/info`.

The cache is initialized at boot and updated only by append/replace events - never by a
timer and never by a request. `ChainValidator` binds the injected consensus parameters and
the resolver holder, so every call site validates with the same checklist and keys. That
binding lives in `node.validation_gateway`, the single FR-25 validation entry point.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, replace

from blockchain_core import Block, ValidationResult
from node.validation_gateway import ChainValidator

QUORUM_HEALTHY = "healthy"
QUORUM_INVALID = "quorum_invalid"  # the chain failed the commit-quorum check
# Two differently-finalized PBFT blocks at one height were observed (UC-3-EC1). Sticky: a safety
# violation stays visible until an operator restarts the node. Slice 18 adds
# `view_change_in_progress` and `crash_fault_quorum_loss`.
QUORUM_BYZANTINE = "byzantine_event_detected"


@dataclass(frozen=True)
class CacheSnapshot:
  chain_valid: bool
  first_invalid_index: int | None
  failure_type: str | None
  tip_index: int
  quorum_status: str


def _snapshot(result: ValidationResult, tip_index: int) -> CacheSnapshot:
  quorum = QUORUM_INVALID if result.failure_type == "quorum" else QUORUM_HEALTHY
  return CacheSnapshot(
    chain_valid=result.valid,
    first_invalid_index=result.first_invalid_index,
    failure_type=result.failure_type,
    tip_index=tip_index,
    quorum_status=quorum,
  )


class ValidityCache:
  def __init__(self, validator: ChainValidator) -> None:
    self._validator = validator
    self._tip: Block | None = None
    self._snapshot: CacheSnapshot | None = None
    self._byzantine = False

  @property
  def snapshot(self) -> CacheSnapshot:
    if self._snapshot is None:
      raise RuntimeError("validity cache is not initialized")
    return self._snapshot

  def initialize(self, blocks: Sequence[Block], result: ValidationResult | None = None) -> None:
    """Boot: reuse the restore-time `result` when given, else validate fully once."""
    outcome = result if result is not None else self._validator.full(blocks)
    self._tip = blocks[-1]
    self._snapshot = _snapshot(outcome, len(blocks) - 1)

  # Each event is split into a fallible `plan_*` (computes the next snapshot, changes nothing)
  # and an infallible `install`, so `ChainState` can do all fallible work before it persists.

  def plan_replace(self, blocks: Sequence[Block], result: ValidationResult) -> CacheSnapshot:
    return _snapshot(result, len(blocks) - 1)

  def plan_append(self, block: Block, result: ValidationResult | None = None) -> CacheSnapshot:
    current = self.snapshot
    tip = self._tip
    if tip is None:
      raise RuntimeError("validity cache is not initialized")
    tip_index = current.tip_index + 1
    if current.chain_valid:
      outcome = result if result is not None else self._validator.extension(tip, [block])
      return _snapshot(outcome, tip_index)
    # an invalid chain stays invalid; only the tip moves
    return CacheSnapshot(
      chain_valid=False,
      first_invalid_index=current.first_invalid_index,
      failure_type=current.failure_type,
      tip_index=tip_index,
      quorum_status=current.quorum_status,
    )

  def install(self, tip: Block, snapshot: CacheSnapshot) -> None:
    self._tip = tip
    self._snapshot = self._sticky(snapshot)

  def flag_byzantine_event(self) -> None:
    """Surface a safety violation via `quorum_status`; only `ChainState` calls this."""
    self._byzantine = True
    self._snapshot = self._sticky(self.snapshot)

  def _sticky(self, snapshot: CacheSnapshot) -> CacheSnapshot:
    return replace(snapshot, quorum_status=QUORUM_BYZANTINE) if self._byzantine else snapshot

  def on_replace(self, blocks: Sequence[Block], result: ValidationResult) -> None:
    """A replaced chain, with the full-validation `result` it was accepted on (no re-run)."""
    self.install(blocks[-1], self.plan_replace(blocks, result))

  def on_append(self, block: Block, result: ValidationResult | None = None) -> None:
    """Validate only the new block against the trusted tip - O(1), no full revalidation.
    `result` is that extension check when the caller (`ChainState`) already ran it."""
    self.install(block, self.plan_append(block, result))
