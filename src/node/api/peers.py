"""POST /peers/register and GET /peers - PeerInfo only, never the ValidatorSet."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field, field_validator

from blockchain_core import public_key_from_pem, public_key_to_pem
from blockchain_core.keys import is_acceptable_public_key
from node.errors import ApiError
from node.peers.registry import PeerInfo, PeerKeyMismatchError

router = APIRouter()


class RegisterRequest(BaseModel):
  node_id: Annotated[str, Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")]
  host: Annotated[str, Field(pattern=r"^[A-Za-z0-9.-]{1,253}$")]
  port: Annotated[int, Field(ge=1, le=65535)]
  public_key: Annotated[str, Field(max_length=2048)]

  @field_validator("public_key")
  @classmethod
  def _pem(cls, value: str) -> str:
    try:
      key = public_key_from_pem(value.encode("utf-8"))
    except Exception:
      raise ValueError("public_key is not a valid PEM public key") from None
    if not is_acceptable_public_key(key):
      raise ValueError("public_key is not an acceptable key type or size")
    return value


class PeerOut(RegisterRequest):
  last_seen: int | None = None


class PeerList(BaseModel):
  peers: list[PeerOut]


def _out(info: PeerInfo) -> PeerOut:
  return PeerOut.model_construct(**info.__dict__)


@router.post("/peers/register", response_model=PeerList)
async def register_peer(body: RegisterRequest, request: Request) -> PeerList:
  context = request.app.state.context
  try:
    context.peers.register(body.node_id, body.host, body.port, body.public_key)
  except PeerKeyMismatchError:
    raise ApiError(
      409, "peer_key_mismatch", f"{body.node_id!r} is already registered with a different key"
    ) from None
  # Include this node itself so the registrant learns its identity; exclude the registrant.
  own = PeerOut.model_construct(
    node_id=context.config.node_id,
    host=context.config.node_host,
    port=context.config.node_port,
    public_key=public_key_to_pem(context.state.node_key.public_key).decode("ascii"),
    last_seen=None,
  )
  others = [_out(p) for p in context.peers.list() if p.node_id != body.node_id]
  return PeerList.model_construct(peers=[own, *others])


@router.get("/peers", response_model=PeerList)
async def list_peers(request: Request) -> PeerList:
  return PeerList.model_construct(peers=[_out(p) for p in request.app.state.context.peers.list()])
