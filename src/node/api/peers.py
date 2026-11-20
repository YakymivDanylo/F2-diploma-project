"""POST /peers/register and GET /peers - PeerInfo only, never the ValidatorSet.

Every registration (and every gossiped entry) is a signed registration (`node.peers.attestation`)
with a fresh `issued_at`: a ValidatorSet identity signed by the key the ValidatorSet holds for
it now, any other identity by the key it registers (proof of possession). The address must be
routable: loopback / localhost (unless ALLOW_LOOPBACK_PEERS), link-local, unspecified,
multicast and this node's own address are refused.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Annotated

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, Field, field_validator

from blockchain_core import public_key_from_pem, public_key_to_pem
from blockchain_core.keys import is_acceptable_public_key
from node.errors import ApiError
from node.patterns import NODE_ID_RE, SIGNATURE_RE
from node.peers.attestation import (
  RegistrationError,
  check_peer_registration,
  check_registration,
  normalized_pem,
  sign_registration,
)
from node.peers.registry import (
  PeerInfo,
  PeerKeyMismatchError,
  PeerRegistryFullError,
  StaleRegistrationError,
  peer_address_problem,
)

if TYPE_CHECKING:
  from node.context import NodeContext

MAX_PEERS_PAGE = 256  # GET /peers page size cap and register-reply size cap

router = APIRouter()


class RegisterRequest(BaseModel):
  node_id: Annotated[str, Field(pattern=NODE_ID_RE.pattern)]
  host: Annotated[str, Field(pattern=r"^[A-Za-z0-9.-]{1,253}$")]
  port: Annotated[int, Field(ge=1, le=65535)]
  public_key: Annotated[str, Field(max_length=2048)]
  issued_at: Annotated[int | None, Field(ge=0)] = None  # epoch ms; signed registration
  signature: Annotated[str | None, Field(pattern=SIGNATURE_RE.pattern)] = None

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


def is_validator_id(context: NodeContext, node_id: str) -> bool:
  return node_id in context.resolvers.current.known_node_ids


def registration_error(
  context: NodeContext,
  *,
  node_id: str,
  host: str,
  port: int,
  public_key: str,
  issued_at: int | None,
  signature: str | None,
  held: PeerInfo | None,
) -> RegistrationError | None:
  """None when the registration of `node_id` may be stored: a routable address and a fresh
  registration signed by the validator's current key (ValidatorSet identity) or by the key it
  registers (any other identity), not older than `held` (the entry held for `node_id`) beyond
  the skew tolerance. Shared by the endpoint and the gossip merge of seed replies. It never
  touches the peer registry (the caller passes `held`), so the gossip merge can run it off
  the event loop. This node's own id is ignored by the registry and needs no check."""
  config = context.config
  if node_id == config.node_id:
    return None
  problem = peer_address_problem(
    host,
    port,
    own_host=config.node_host,
    own_port=config.node_port,
    allow_loopback=config.allow_loopback_peers,
  )
  if problem is not None:
    return RegistrationError(422, "invalid_peer_address", problem)
  held_issued_at = held.held_issued_at if held is not None else None
  resolver = context.resolvers.current
  try:
    if node_id in resolver.known_node_ids:
      check_registration(
        node_id=node_id,
        host=host,
        port=port,
        public_key=public_key,
        issued_at=issued_at,
        signature=signature,
        resolve_node_key=resolver.resolve_node_key,
        now_ms=now_ms(),
        max_future_skew_ms=config.max_future_skew_ms,
        held_issued_at=held_issued_at,
      )
    else:
      check_peer_registration(
        node_id=node_id,
        host=host,
        port=port,
        public_key=public_key,
        issued_at=issued_at,
        signature=signature,
        now_ms=now_ms(),
        max_future_skew_ms=config.max_future_skew_ms,
        held_issued_at=held_issued_at,
      )
  except RegistrationError as error:
    return error
  return None


def gossip_accept(context: NodeContext) -> Callable[[PeerOut, PeerInfo | None], str | None]:
  """The `accept` check for `merge_peer_list` / `register_with_seeds`: the key to store for
  an acceptable entry (the same `stored_public_key` the endpoint stores), else None. It reads
  no registry state (the merge passes the held entry), so it is safe to run off the loop."""

  def accept(entry: PeerOut, held: PeerInfo | None) -> str | None:
    error = registration_error(
      context,
      node_id=entry.node_id,
      host=entry.host,
      port=entry.port,
      public_key=entry.public_key,
      issued_at=entry.issued_at,
      signature=entry.signature,
      held=held,
    )
    if error is not None:
      return None
    return stored_public_key(context, entry.node_id, entry.public_key)

  return accept


def validator_key_now(context: NodeContext) -> Callable[[str], str | None]:
  """`key_now` for the gossip merge: the PEM (as `stored_public_key` stores it) of the key the
  ValidatorSet holds for a validator id at this moment, None when it holds none."""

  def key_now(node_id: str) -> str | None:
    resolver = context.resolvers.current
    if node_id not in resolver.known_node_ids:
      return None
    key = resolver.resolve_node_key(node_id, now_ms())
    return None if key is None else public_key_to_pem(key).decode("ascii")

  return key_now


def stored_public_key(context: NodeContext, node_id: str, public_key: str) -> str:
  """The key to store, for the endpoint and the gossip merge alike: the ValidatorSet key for
  a validator id, else the normalized PEM."""
  resolver = context.resolvers.current
  if node_id in resolver.known_node_ids:
    key = resolver.resolve_node_key(node_id, now_ms())
    if key is not None:
      return public_key_to_pem(key).decode("ascii")
  return normalized_pem(public_key) or public_key


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
  # Every identity needs a fresh registration signed with its key (a ValidatorSet identity:
  # the key the ValidatorSet holds now): otherwise anyone could squat ids, or move a peer's
  # address to another host.
  error = registration_error(
    context,
    node_id=body.node_id,
    host=body.host,
    port=body.port,
    public_key=body.public_key,
    issued_at=body.issued_at,
    signature=body.signature,
    held=context.peers.get(body.node_id),
  )
  if error is not None:
    raise ApiError(error.status, error.code, error.message)
  try:
    context.peers.register(
      body.node_id,
      body.host,
      body.port,
      stored_public_key(context, body.node_id, body.public_key),
      issued_at=body.issued_at,
      signature=body.signature,
    )
  except PeerRegistryFullError:
    raise ApiError(503, "peer_registry_full", "the peer registry is full") from None
  except PeerKeyMismatchError:  # non-validators only: a validator id takes its current key
    raise ApiError(
      409, "peer_key_mismatch", f"{body.node_id!r} is already registered with a different key"
    ) from None
  except StaleRegistrationError:  # older than held (inside the skew) and a different address
    raise ApiError(
      409, "stale_registration", "a newer registration for this peer is already held"
    ) from None
  # Include this node itself so the registrant learns its identity; exclude the registrant.
  own = own_entry(context, now_ms())
  others = [_out(p) for p in context.peers.list() if p.node_id != body.node_id]
  return PeerList.model_construct(peers=[own, *others[: MAX_PEERS_PAGE - 1]])


@router.get("/peers", response_model=PeerList)
async def list_peers(
  request: Request,
  limit: Annotated[int, Query(ge=1, le=MAX_PEERS_PAGE)] = MAX_PEERS_PAGE,
  offset: Annotated[int, Query(ge=0)] = 0,
) -> PeerList:
  peers = request.app.state.context.peers.list()[offset : offset + limit]
  return PeerList.model_construct(peers=[_out(p) for p in peers])
