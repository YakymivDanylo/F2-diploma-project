"""GET /chain?from=&to= - always a bounded, inclusive range (never a full dump)."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel

from blockchain_core.storage.chain_store import block_to_dict
from node.errors import ApiError

router = APIRouter()


class ChainPage(BaseModel):
  from_index: int
  to_index: int | None  # last index returned; null when the page is empty
  tip_index: int
  truncated: bool  # the request exceeded the page cap and was shortened
  blocks: list[dict[str, Any]]


@router.get("/chain", response_model=ChainPage)
async def get_chain(
  request: Request,
  from_: Annotated[int, Query(alias="from", ge=0)] = 0,
  to: Annotated[int | None, Query(ge=0)] = None,
) -> ChainPage:
  context = request.app.state.context
  blocks = context.state.restored.blocks
  tip = len(blocks) - 1
  cap = context.config.max_page_size
  if to is not None and to < from_:
    raise ApiError(422, "invalid_range", "'to' must be >= 'from'", {"from": from_, "to": to})
  page_end = from_ + cap - 1
  requested_end = page_end if to is None else to
  truncated = requested_end > page_end or (to is None and tip > page_end)
  if from_ > tip:
    return ChainPage(from_index=from_, to_index=None, tip_index=tip, truncated=False, blocks=[])
  end = min(requested_end, page_end, tip)
  return ChainPage(
    from_index=from_,
    to_index=end,
    tip_index=tip,
    truncated=truncated,
    blocks=[block_to_dict(b) for b in blocks[from_ : end + 1]],
  )
