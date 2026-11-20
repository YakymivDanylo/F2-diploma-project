"""PBFT wire messages, each signed by its sender's node key.

Every message is `{type, view, seq, block_hash, node_id, signature, ...}`:
- `pbft_pre_prepare` also carries the proposer-signed candidate `block`, and - when the block
  is carried over from an earlier view - the prepared certificate `cert` that justifies it;
- `pbft_prepare` and `pbft_commit` are votes for `(view, seq, block_hash)`;
- `pbft_view_change` (Slice 18) is a vote to move to view `view`; it carries the block this node
  is locked on at `seq` and that block's prepared certificate, or `NO_BLOCK` / nulls;
- `pbft_new_view` carries the view-change votes (signatures only) that justify an installed
  view, so a node that missed them - or rejoins after a restart - can adopt the view.

Signature domains never overlap, so no message can be replayed as another kind:
- pre-prepare, prepare, view-change and new-view sign their OWN domain tags over
  `{view, seq, block_hash, node_id}` (never the bare preimage, so none can pass as a
  `proposer_signature`);
- a commit vote is exactly `sign_commit` over `commit_payload(block_hash)` - the payload the
  core's `commit_signatures` quorum check verifies, so a finalized block carries the votes as
  received. `seq` is bound through `block_hash` (it covers the block's `index`). A commit is
  view-independent: any quorum of valid commits for a hash proves it final in whatever view.

A prepared certificate is the primary's pre-prepare signature plus prepare signatures of
distinct other members for one `(view, seq, block_hash)`, a quorum in all: proof that a quorum
prepared the block in that view. It is transferable and verified with ValidatorSet keys.

Signatures are verified with the sender's key from the ValidatorSet resolver, never with a key
carried in a message.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

from blockchain_core import Block, commit_payload, sign_canonical, verify_canonical
from blockchain_core.keys import PrivateKey, PublicKey

PRE_PREPARE = "pbft_pre_prepare"
PREPARE = "pbft_prepare"
COMMIT = "pbft_commit"
VIEW_CHANGE = "pbft_view_change"
NEW_VIEW = "pbft_new_view"
MESSAGE_TYPES = frozenset({PRE_PREPARE, PREPARE, COMMIT, VIEW_CHANGE, NEW_VIEW})

PRE_PREPARE_DOMAIN = "node/pbft-pre-prepare/v1"
PREPARE_DOMAIN = "node/pbft-prepare/v1"
VIEW_CHANGE_DOMAIN = "node/pbft-view-change/v1"
NEW_VIEW_DOMAIN = "node/pbft-new-view/v1"
_DOMAINS = {
  PRE_PREPARE: PRE_PREPARE_DOMAIN,
  PREPARE: PREPARE_DOMAIN,
  VIEW_CHANGE: VIEW_CHANGE_DOMAIN,
  NEW_VIEW: NEW_VIEW_DOMAIN,
}
NO_BLOCK = "0" * 64  # a view-change vote from a node that is not locked on any block

MAX_COUNTER = 2**53  # view / seq: JSON-safe and far beyond any real chain
MAX_VOTES = 64  # prepares in a certificate / votes in a new-view: bounded by the ValidatorSet
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_SIG_RE = re.compile(r"^(?:[0-9a-f]{2}){1,512}$")  # whole bytes only

Kind = Literal[
  "pbft_pre_prepare", "pbft_prepare", "pbft_commit", "pbft_view_change", "pbft_new_view"
]


class MalformedMessage(ValueError):
  """A PBFT message that does not have the exact expected shape."""


@dataclass(frozen=True)
class PreparedCert:
  """A quorum prepared `block_hash` at `seq` in `view` (see the module docstring)."""

  view: int
  seq: int
  block_hash: str
  primary_signature: str  # the pre-prepare signature of primary_of(view)
  prepares: tuple[tuple[str, str], ...]  # (node_id, prepare signature), sorted by node_id

  def to_wire(self) -> dict[str, Any]:
    return {
      "view": self.view,
      "seq": self.seq,
      "block_hash": self.block_hash,
      "primary_signature": self.primary_signature,
      "prepares": [{"node_id": n, "signature": s} for n, s in self.prepares],
    }


@dataclass(frozen=True)
class Vote:
  """A view-change vote reduced to what its signature covers (inside a new-view)."""

  view: int
  seq: int
  block_hash: str
  node_id: str
  signature: str

  def to_wire(self) -> dict[str, Any]:
    return {
      "view": self.view,
      "seq": self.seq,
      "block_hash": self.block_hash,
      "node_id": self.node_id,
      "signature": self.signature,
    }


@dataclass(frozen=True)
class PbftMessage:
  kind: Kind
  view: int
  seq: int
  block_hash: str
  node_id: str
  signature: str
  block: Any = None  # pre-prepare / view-change: the raw block dict (or None), decoded later
  cert: PreparedCert | None = None  # pre-prepare (carried block) / view-change
  votes: tuple[Vote, ...] = ()  # new-view only

  def to_wire(self) -> dict[str, Any]:
    wire: dict[str, Any] = {
      "type": self.kind,
      "view": self.view,
      "seq": self.seq,
      "block_hash": self.block_hash,
      "node_id": self.node_id,
      "signature": self.signature,
    }
    if self.kind == PRE_PREPARE:
      wire["block"] = self.block
      if self.cert is not None:
        wire["cert"] = self.cert.to_wire()
    elif self.kind == VIEW_CHANGE:
      wire["block"] = self.block
      wire["cert"] = None if self.cert is None else self.cert.to_wire()
    elif self.kind == NEW_VIEW:
      wire["votes"] = [vote.to_wire() for vote in self.votes]
    return wire

  def vote(self) -> Vote:
    return Vote(self.view, self.seq, self.block_hash, self.node_id, self.signature)


def vote_payload(kind: Kind, view: int, seq: int, block_hash: str, node_id: str) -> dict[str, Any]:
  """What a message's signature covers. Commit votes sign the core commit payload."""
  if kind == COMMIT:
    return commit_payload(block_hash)
  return {
    "domain": _DOMAINS[kind],
    "view": view,
    "seq": seq,
    "block_hash": block_hash,
    "node_id": node_id,
  }


def sign_vote(
  kind: Kind, key: PrivateKey, *, view: int, seq: int, block_hash: str, node_id: str
) -> str:
  return sign_canonical(key, vote_payload(kind, view, seq, block_hash, node_id))


def make_message(
  kind: Kind,
  key: PrivateKey,
  *,
  view: int,
  seq: int,
  block_hash: str,
  node_id: str,
  block: Any = None,
  cert: PreparedCert | None = None,
  votes: tuple[Vote, ...] = (),
) -> PbftMessage:
  signature = sign_vote(kind, key, view=view, seq=seq, block_hash=block_hash, node_id=node_id)
  return PbftMessage(kind, view, seq, block_hash, node_id, signature, block, cert, votes)


def verify_message(message: PbftMessage, key: PublicKey) -> bool:
  payload = vote_payload(
    message.kind, message.view, message.seq, message.block_hash, message.node_id
  )
  return verify_canonical(key, payload, message.signature)


def verify_vote(vote: Vote, key: PublicKey) -> bool:
  payload = vote_payload(VIEW_CHANGE, vote.view, vote.seq, vote.block_hash, vote.node_id)
  return verify_canonical(key, payload, vote.signature)


def block_view(block: Block) -> int | None:
  """The view a block was proposed in (`sealed_consensus == {"view_number": v}`), else None."""
  sealed = dict(block.sealed_consensus)
  view = sealed.get("view_number")
  if set(sealed) != {"view_number"} or type(view) is not int or view < 0:
    return None
  return view


def matches_block(message: PbftMessage, block: Block) -> bool:
  """The message's (seq, block_hash) are the block's, and the block was proposed in the
  message's view (fresh) or, carried over with a certificate, in an earlier one."""
  view = block_view(block)
  return (
    message.block_hash == block.block_hash
    and message.seq == block.index
    and view is not None
    and view <= message.view
  )


def verify_cert(
  cert: PreparedCert,
  *,
  primary_of: Callable[[int], str | None],
  members: frozenset[str],
  quorum: int,
  resolve_key: Callable[[str], PublicKey | None],
  key_id: Callable[[PublicKey], bytes],
) -> bool:
  """True when `cert` holds the view's primary's pre-prepare signature plus valid prepares of
  distinct OTHER members (and distinct keys) - a quorum in all."""
  primary = primary_of(cert.view)
  if primary is None or len(cert.prepares) > len(members):
    return False
  primary_key = resolve_key(primary)
  pre = vote_payload(PRE_PREPARE, cert.view, cert.seq, cert.block_hash, primary)
  if primary_key is None or not verify_canonical(primary_key, pre, cert.primary_signature):
    return False
  signers, keys = {primary}, {key_id(primary_key)}
  for node_id, signature in cert.prepares:
    if node_id in signers or node_id not in members:
      continue
    key = resolve_key(node_id)
    if key is None or key_id(key) in keys:
      continue
    payload = vote_payload(PREPARE, cert.view, cert.seq, cert.block_hash, node_id)
    if verify_canonical(key, payload, signature):
      signers.add(node_id)
      keys.add(key_id(key))
  return len(signers) >= quorum


# --------------------------------------------------------------------------- decoding


def _counter(value: object, name: str) -> int:
  if type(value) is not int or not 0 <= value < MAX_COUNTER:
    raise MalformedMessage(f"{name} must be a non-negative integer")
  return value


def _text(value: object, pattern: re.Pattern[str], name: str) -> str:
  if not isinstance(value, str) or not pattern.fullmatch(value):
    raise MalformedMessage(f"{name} is malformed")
  return value


def _exact(raw: object, keys: set[str], name: str) -> dict[str, Any]:
  if not isinstance(raw, dict) or set(raw) != keys:
    raise MalformedMessage(f"{name} has unexpected or missing fields")
  return raw


def decode_cert(raw: object) -> PreparedCert:
  data = _exact(raw, {"view", "seq", "block_hash", "primary_signature", "prepares"}, "cert")
  prepares = data["prepares"]
  if not isinstance(prepares, list) or len(prepares) > MAX_VOTES:
    raise MalformedMessage("cert prepares must be a bounded list")
  pairs = []
  for item in prepares:
    entry = _exact(item, {"node_id", "signature"}, "cert prepare")
    pairs.append(
      (_text(entry["node_id"], _ID_RE, "node_id"), _text(entry["signature"], _SIG_RE, "signature"))
    )
  return PreparedCert(
    view=_counter(data["view"], "view"),
    seq=_counter(data["seq"], "seq"),
    block_hash=_text(data["block_hash"], _HASH_RE, "block_hash"),
    primary_signature=_text(data["primary_signature"], _SIG_RE, "signature"),
    prepares=tuple(sorted(pairs)),
  )


def _decode_vote(raw: object) -> Vote:
  data = _exact(raw, {"view", "seq", "block_hash", "node_id", "signature"}, "vote")
  return Vote(
    view=_counter(data["view"], "view"),
    seq=_counter(data["seq"], "seq"),
    block_hash=_text(data["block_hash"], _HASH_RE, "block_hash"),
    node_id=_text(data["node_id"], _ID_RE, "node_id"),
    signature=_text(data["signature"], _SIG_RE, "signature"),
  )


def decode_message(raw: dict[str, Any]) -> PbftMessage:
  """Strict decode; any missing, extra or ill-typed field raises `MalformedMessage`."""
  kind = raw.get("type")
  if kind not in MESSAGE_TYPES:
    raise MalformedMessage("unknown PBFT message type")
  base = {"type", "view", "seq", "block_hash", "node_id", "signature"}
  if kind == PRE_PREPARE:
    allowed = [base | {"block"}, base | {"block", "cert"}]  # cert only for a carried block
  elif kind == VIEW_CHANGE:
    allowed = [base | {"block", "cert"}]
  elif kind == NEW_VIEW:
    allowed = [base | {"votes"}]
  else:
    allowed = [base]
  if set(raw) not in allowed:
    raise MalformedMessage("unexpected or missing fields")
  block = raw.get("block")
  cert_raw = raw.get("cert")
  if kind == PRE_PREPARE and not isinstance(block, dict):
    raise MalformedMessage("pre-prepare must carry a block object")
  if kind == PRE_PREPARE and "cert" in raw and cert_raw is None:
    raise MalformedMessage("a pre-prepare cert, when present, is an object")
  if kind == VIEW_CHANGE:
    locked = raw.get("block_hash") != NO_BLOCK
    if locked != isinstance(block, dict) or locked != (cert_raw is not None):
      raise MalformedMessage("a view-change carries block and cert exactly when it names one")
  votes: tuple[Vote, ...] = ()
  if kind == NEW_VIEW:
    items = raw["votes"]
    if not isinstance(items, list) or not 0 < len(items) <= MAX_VOTES:
      raise MalformedMessage("new-view votes must be a bounded, non-empty list")
    votes = tuple(_decode_vote(item) for item in items)
  return PbftMessage(
    kind=kind,
    view=_counter(raw["view"], "view"),
    seq=_counter(raw["seq"], "seq"),
    block_hash=_text(raw["block_hash"], _HASH_RE, "block_hash"),
    node_id=_text(raw["node_id"], _ID_RE, "node_id"),
    signature=_text(raw["signature"], _SIG_RE, "signature"),
    block=block,
    cert=None if cert_raw is None else decode_cert(cert_raw),
    votes=votes,
  )
