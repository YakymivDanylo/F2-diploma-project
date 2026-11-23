"""Per-block consensus metrics. Only completed blocks are ever recorded (UC-9-EC1)."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

MAX_RETAINED = 10_000


@dataclass(frozen=True)
class ConsensusMetric:
  block_index: int
  algorithm: str
  proposed_at: int  # wall-clock ms when work on the block began
  finalized_at: int  # wall-clock ms when the block was appended
  attempts_or_rounds: int  # PoW: hash attempts (arbitrary-size int); PBFT: round trips
  hash_rate: float | None = None  # PoW only: attempts per second, a node-local sample

  @property
  def time_to_finalize_ms(self) -> int:
    return self.finalized_at - self.proposed_at


class MetricsRecorder:
  def __init__(self, max_retained: int = MAX_RETAINED) -> None:
    self._rows: deque[ConsensusMetric] = deque(maxlen=max_retained)

  def record(self, metric: ConsensusMetric) -> None:
    self._rows.append(metric)

  def rows(self, last: int | None = None) -> list[ConsensusMetric]:
    rows = list(self._rows)
    return rows if last is None else rows[-last:]

  def __len__(self) -> int:
    return len(self._rows)
