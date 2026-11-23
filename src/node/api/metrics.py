"""GET /metrics/consensus - completed blocks only, newest last."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel

router = APIRouter()


class MetricOut(BaseModel):
  block_index: int
  algorithm: str
  proposed_at: int
  finalized_at: int
  time_to_finalize_ms: int
  attempts_or_rounds: int
  hash_rate: float | None


@router.get("/metrics/consensus", response_model=list[MetricOut])
async def consensus_metrics(
  request: Request,
  last: Annotated[int | None, Query(ge=1, le=10_000)] = None,
) -> list[MetricOut]:
  rows = request.app.state.context.metrics.rows(last)
  return [
    MetricOut(
      block_index=row.block_index,
      algorithm=row.algorithm,
      proposed_at=row.proposed_at,
      finalized_at=row.finalized_at,
      time_to_finalize_ms=row.time_to_finalize_ms,
      attempts_or_rounds=row.attempts_or_rounds,
      hash_rate=row.hash_rate,
    )
    for row in rows
  ]
