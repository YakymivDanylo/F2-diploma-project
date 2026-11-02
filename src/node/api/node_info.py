"""GET /node/info - served entirely from the validity cache, O(1) in chain length."""

from __future__ import annotations

from fastapi import APIRouter, Request
from pydantic import BaseModel

from blockchain_core import public_key_to_pem

router = APIRouter()


class NodeInfo(BaseModel):
  node_id: str
  algorithm: str
  n: int
  f: int
  node_public_key: str
  tip_index: int
  chain_valid: bool
  first_invalid_index: int | None
  quorum_status: str


@router.get("/node/info", response_model=NodeInfo)
async def node_info(request: Request) -> NodeInfo:
  context = request.app.state.context
  snapshot = context.validity_cache.snapshot
  return NodeInfo(
    node_id=context.config.node_id,
    algorithm=context.config.consensus_mode,
    # n/f come from the configured ValidatorSet even in PoW mode, where they carry no
    # quorum semantics (CN-TC-12.6).
    n=context.validators.n,
    f=context.validators.f,
    node_public_key=public_key_to_pem(context.state.node_key.public_key).decode("ascii"),
    tip_index=snapshot.tip_index,
    chain_valid=snapshot.chain_valid,
    first_invalid_index=snapshot.first_invalid_index,
    quorum_status=snapshot.quorum_status,
  )
