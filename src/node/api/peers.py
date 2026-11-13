"""POST /peers/register and GET /peers - PeerInfo only, never the ValidatorSet.

A ValidatorSet identity is registered (and gossiped) only with a registration signed by that
validator's node key (`node.peers.attestation`), so nobody can redirect a validator's address.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Annotated

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field, field_validator

from blockchain_core import public_key_from_pem, public_key_to_pem
from blockchain_core.keys import is_acceptable_public_key
from node.errors import ApiError
from node.peers.attestation import RegistrationError, check_registration, sign_registration
from node.peers.registry import PeerInfo, PeerKeyMismatchError, PeerRegistryFullError

if TYPE_CHECKING:
  from node.main import NodeContext

router = APIRouter()


class RegisterRequest(BaseModel):
  node_id: Annotated[str, Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")]
  host: Annotated[str, Field(pattern=r"^[A-Za-z0-9.-]{1,253}$")]
  port: Annotated[int, Field(ge=1, le=65535)]
  public_key: Annotated[str, Field(max_length=2048)]
  issued_at: Annotated[int | None, Field(ge=0)] = None  # epoch ms; signed registration
  signature: Annotated[str | None, Field(pattern=r"^[0-9a-f]{2,1024}$")] = None

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


def now_ms() -> int:
  return int(time.time() * 1000)


def validator_registration_error(
  context: NodeContext,
  *,
  node_id: str,
  host: str,
  port: int,
  public_key: str,
  issued_at: int | None,
  signature: str | None,
) -> RegistrationError | None:
  """None when `node_id` is not a ValidatorSet identity or its registration is valid and fresh;
  shared by the endpoint and the gossip merge of seed replies."""
  resolver = context.resolvers.current
  if node_id == context.config.node_id or node_id not in resolver.known_node_ids:
    return None
  held = context.peers.get(node_id)
  try:
    check_registration(
      node_id=node_id,
      host=host,
      port=port,
      public_key=public_key,
      issued_at=issued_at,
      signature=signature,
      resolve_node_key=resolver.resolve_node_key,
      now_ms=now_ms(),
      max_future_skew_ms=context.config.max_future_skew_ms,
      held_issued_at=held.issued_at if held is not None else None,
    )
  except RegistrationError as error:
    return error
  return None


def own_entry(context: NodeContext, issued_at: int) -> PeerOut:
  """This node's own entry, signed, so a receiver can accept it as a validator registration."""
  pem = public_key_to_pem(context.state.node_key.public_key).decode("ascii")
  config = context.config
  return PeerOut.model_construct(
    node_id=config.node_id,
    host=config.node_host,
    port=config.node_port,
    public_key=pem,
    issued_at=issued_at,
    signature=sign_registration(
      context.state.node_key.private_key,
      config.node_id,
      config.node_host,
      config.node_port,
      pem,
      issued_at,
    ),
    last_seen=None,
  )


@router.post("/peers/register", response_model=PeerList)
async def register_peer(body: RegisterRequest, request: Request) -> PeerList:
  context = request.app.state.context
  # A ValidatorSet identity needs its configured key AND a fresh registration signed with it:
  # otherwise anyone could squat a validator's id, or move its address to another host.
  error = validator_registration_error(
    context,
    node_id=body.node_id,
    host=body.host,
    port=body.port,
    public_key=body.public_key,
    issued_at=body.issued_at,
    signature=body.signature,
  )
  if error is not None:
    raise ApiError(error.status, error.code, error.message)
  try:
    context.peers.register(
      body.node_id,
      body.host,
      body.port,
      body.public_key,
      issued_at=body.issued_at,
      signature=body.signature,
    )
  except PeerRegistryFullError:
    raise ApiError(503, "peer_registry_full", "the peer registry is full") from None
  except PeerKeyMismatchError:
    raise ApiError(
      409, "peer_key_mismatch", f"{body.node_id!r} is already registered with a different key"
    ) from None
  # Include this node itself so the registrant learns its identity; exclude the registrant.
  own = own_entry(context, now_ms())
  others = [_out(p) for p in context.peers.list() if p.node_id != body.node_id]
  return PeerList.model_construct(peers=[own, *others])


@router.get("/peers", response_model=PeerList)
async def list_peers(request: Request) -> PeerList:
  return PeerList.model_construct(peers=[_out(p) for p in request.app.state.context.peers.list()])
