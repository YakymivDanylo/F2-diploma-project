"""Cached chain validity behind `GET /node/info`.

The chain part of the cache is initialized at boot and updated only by append/replace events -
never by a timer and never by a request. Under PBFT the engine also reports its liveness
(`set_liveness`), layered over the chain verdict when the snapshot is read.
`ChainValidator` binds the injected consensus parameters and the resolver holder, so every
call site validates with the same checklist and keys. That binding lives in
`node.validation_gateway`, the single FR-25 validation entry point.
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from dataclasses import dataclass, replace

from blockchain_core import Block, ValidationResult
from node.validation_gateway import ChainValidator

QUORUM_HEALTHY = "healthy"
QUORUM_INVALID = "quorum_invalid"  # the chain failed the commit-quorum check
# A Byzantine event was observed: two differently-finalized PBFT blocks at one height (UC-3-EC1)
# or a validator signing two different votes / blocks for one slot (UC-6-E2, UC-8-E4). Sticky: a
# safety violation stays visible until an operator restarts the node.
QUORUM_BYZANTINE = "byzantine_event_detected"
# PBFT liveness, reported by the engine (UC-6-E5, UC-12-EC1). Never conflated with the above:
# a crash fault is "not enough members respond", a Byzantine event is "a member lied".
QUORUM_VIEW_CHANGE = "view_change_in_progress"
QUORUM_CRASH_LOSS = "crash_fault_quorum_loss"
LIVENESS_STATES = frozenset({QUORUM_HEALTHY, QUORUM_VIEW_CHANGE, QUORUM_CRASH_LOSS})
MAX_BYZANTINE_EVENTS = 32  # most recent kept for GET /node/info


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
    self._liveness = QUORUM_HEALTHY
    self._events: list[dict[str, object]] = []

  @property
  def snapshot(self) -> CacheSnapshot:
    """Precedence: byzantine (sticky) > the chain's own quorum verdict > engine liveness."""
    if self._snapshot is None:
      raise RuntimeError("validity cache is not initialized")
    snapshot = self._snapshot
    if snapshot.quorum_status == QUORUM_HEALTHY and self._liveness != QUORUM_HEALTHY:
      return replace(snapshot, quorum_status=self._liveness)
    return snapshot

  @property
  def liveness(self) -> str:
    """The engine's liveness, shown on its own too: a sticky Byzantine status must not hide
    a later crash fault or view change."""
    return self._liveness

  @property
  def byzantine_events(self) -> list[dict[str, object]]:
    return list(self._events)

  def set_liveness(self, status: str) -> None:
    """The PBFT engine's view of liveness: healthy / view change / crash-fault quorum loss."""
    if status not in LIVENESS_STATES:
      raise ValueError(f"unknown liveness status {status!r}")
    self._liveness = status

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
    current = self._raw()
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

  def flag_byzantine_event(self, reason: str = "", *, offender: str | None = None) -> None:
    """Surface a safety violation via `quorum_status` (sticky until the node restarts) and the
    event log; only `ChainState` calls this."""
    self._events.append({"reason": reason, "offender": offender, "at_ms": int(time.time() * 1000)})
    del self._events[:-MAX_BYZANTINE_EVENTS]
    self._byzantine = True
    self._snapshot = self._sticky(self._raw())

  def _raw(self) -> CacheSnapshot:
    if self._snapshot is None:
      raise RuntimeError("validity cache is not initialized")
    return self._snapshot

  def _sticky(self, snapshot: CacheSnapshot) -> CacheSnapshot:
    return replace(snapshot, quorum_status=QUORUM_BYZANTINE) if self._byzantine else snapshot

  def on_replace(self, blocks: Sequence[Block], result: ValidationResult) -> None:
    """A replaced chain, with the full-validation `result` it was accepted on (no re-run)."""
    self.install(blocks[-1], self.plan_replace(blocks, result))

  def on_append(self, block: Block, result: ValidationResult | None = None) -> None:
    """Validate only the new block against the trusted tip - O(1), no full revalidation.
    `result` is that extension check when the caller (`ChainState`) already ran it."""
    self.install(block, self.plan_append(block, result))
