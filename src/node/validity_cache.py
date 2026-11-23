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
# or a validator signing two different votes / blocks for one slot (UC-6-E2, UC-8-E4). Sticky:
# never cleared at run time. Under PBFT the events are persisted in the engine's state file, so
# a restart does NOT clear it either; only an explicit operator reset (`BYZANTINE_RESET_ON_BOOT`)
# does. PoW keeps no PBFT state file: there a restart starts with an empty log.
QUORUM_BYZANTINE = "byzantine_event_detected"
# PBFT liveness, reported by the engine (UC-6-E5, UC-12-EC1). Never conflated with the above:
# a crash fault is "not enough members respond", a Byzantine event is "a member lied".
QUORUM_VIEW_CHANGE = "view_change_in_progress"
QUORUM_CRASH_LOSS = "crash_fault_quorum_loss"
LIVENESS_STATES = frozenset({QUORUM_HEALTHY, QUORUM_VIEW_CHANGE, QUORUM_CRASH_LOSS})
# The Byzantine event log behind GET /node/info is bounded PER OFFENDER, so one Byzantine member
# signing conflicts in fresh (view, seq) slots - a distinct event each time - cannot evict the
# evidence against another offender: the FIRST event of every offender is kept for good, and at
# most MAX_EVENTS_PER_OFFENDER per offender (a newer one replaces that offender's oldest
# non-first event). At most MAX_OFFENDERS distinct offenders (`None`, "unattributed", counts as
# one) are logged; a further offender only raises the sticky status. Offenders are ValidatorSet
# ids or sets of them, so the cap is not reached in practice.
MAX_EVENTS_PER_OFFENDER = 4
MAX_OFFENDERS = 32
MAX_BYZANTINE_EVENTS = MAX_EVENTS_PER_OFFENDER * MAX_OFFENDERS  # overall bound (128)


@dataclass(frozen=True)
class CacheSnapshot:
  chain_valid: bool
  first_invalid_index: int | None
  failure_type: str | None
  tip_index: int
  quorum_status: str


def _event_key(event: dict[str, object]) -> tuple[object, object]:
  return (event["reason"], event["offender"])


def _admit(events: list[dict[str, object]], event: dict[str, object]) -> None:
  """Add `event` to the chronological log `events` in place, by the per-offender policy above;
  deduplicated on (reason, offender) - a divergence sync re-detects every round is kept once."""
  key = _event_key(event)
  if any(_event_key(e) == key for e in events):
    return
  offender = event["offender"]
  mine = [i for i, e in enumerate(events) if e["offender"] == offender]
  if not mine and len({e["offender"] for e in events}) >= MAX_OFFENDERS:
    return
  if len(mine) >= MAX_EVENTS_PER_OFFENDER:
    del events[mine[1]]  # the offender's oldest non-first event; its first stays
  events.append(event)


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
    self._snapshot = self._sticky(_snapshot(outcome, len(blocks) - 1))

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

  def flag_byzantine_event(
    self, reason: str = "", *, offender: str | None = None, at_ms: int | None = None
  ) -> None:
    """Surface a safety violation via `quorum_status` (sticky) and the event log; only
    `ChainState` calls this. Under PBFT the engine persists the log in its state file, so the
    status and the events survive a restart (`restore_byzantine_events`)."""
    when = at_ms if at_ms is not None else int(time.time() * 1000)
    _admit(self._events, {"reason": reason, "offender": offender, "at_ms": when})
    self._mark_byzantine()

  def restore_byzantine_events(self, events: Sequence[dict[str, object]]) -> None:
    """Events persisted before a restart: put back ahead of any reported since boot (bounded
    and deduplicated like `flag_byzantine_event`) and the sticky status restored - not
    reported again as new events."""
    if not events:
      return
    restored = [
      {"reason": e["reason"], "offender": e["offender"], "at_ms": e["at_ms"]} for e in events
    ]
    merged: list[dict[str, object]] = []
    for event in [*restored, *self._events]:
      _admit(merged, event)
    self._events = merged
    self._mark_byzantine()

  def _mark_byzantine(self) -> None:
    self._byzantine = True
    if self._snapshot is not None:
      self._snapshot = self._sticky(self._snapshot)

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
