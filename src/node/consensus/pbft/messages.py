"""PBFT wire messages: pre-prepare, prepare and commit, each signed by its sender's node key.

Every message is `{type, view, seq, block_hash, node_id, signature}`; a pre-prepare also
carries the proposer-signed candidate `block`. The vote a message expresses is keyed by
`(view, seq, block_hash)`.

Signature domains never overlap, so no message can be replayed as another kind:
- pre-prepare and prepare sign their OWN domain tags over `{view, seq, block_hash, node_id}`
  (never the bare preimage, so neither can pass as a `proposer_signature`);
- a commit vote is exactly `sign_commit` over `commit_payload(block_hash)` - the payload the
  core's `commit_signatures` quorum check verifies, so a finalized block carries the votes as
  received. `view` and `seq` are bound through `block_hash`, which covers the block's `index`
  (= seq) and `sealed_consensus.view_number` (= view); the receiver checks both match.

Signatures are verified with the sender's key from the ValidatorSet resolver, never with a key
carried in a message.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal

from blockchain_core import Block, commit_payload, sign_canonical, verify_canonical
from blockchain_core.keys import PrivateKey, PublicKey

PRE_PREPARE = "pbft_pre_prepare"
PREPARE = "pbft_prepare"
COMMIT = "pbft_commit"
MESSAGE_TYPES = frozenset({PRE_PREPARE, PREPARE, COMMIT})

PRE_PREPARE_DOMAIN = "node/pbft-pre-prepare/v1"
PREPARE_DOMAIN = "node/pbft-prepare/v1"

MAX_COUNTER = 2**53  # view / seq: JSON-safe and far beyond any real chain
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_SIG_RE = re.compile(r"^(?:[0-9a-f]{2}){1,512}$")  # whole bytes only

Kind = Literal["pbft_pre_prepare", "pbft_prepare", "pbft_commit"]


class MalformedMessage(ValueError):
  """A PBFT message that does not have the exact expected shape."""


@dataclass(frozen=True)
class PbftMessage:
  kind: Kind
  view: int
  seq: int
  block_hash: str
  node_id: str
  signature: str
  block: Any = None  # pre-prepare only: the raw block dict, decoded by the engine

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
    return wire


def vote_payload(kind: Kind, view: int, seq: int, block_hash: str, node_id: str) -> dict[str, Any]:
  """What a message's signature covers. Commit votes sign the core commit payload."""
  if kind == COMMIT:
    return commit_payload(block_hash)
  domain = PRE_PREPARE_DOMAIN if kind == PRE_PREPARE else PREPARE_DOMAIN
  return {"domain": domain, "view": view, "seq": seq, "block_hash": block_hash, "node_id": node_id}


def make_message(
  kind: Kind,
  key: PrivateKey,
  *,
  view: int,
  seq: int,
  block_hash: str,
  node_id: str,
  block: Any = None,
) -> PbftMessage:
  signature = sign_canonical(key, vote_payload(kind, view, seq, block_hash, node_id))
  return PbftMessage(kind, view, seq, block_hash, node_id, signature, block)


def verify_message(message: PbftMessage, key: PublicKey) -> bool:
  payload = vote_payload(
    message.kind, message.view, message.seq, message.block_hash, message.node_id
  )
  return verify_canonical(key, payload, message.signature)


def matches_block(message: PbftMessage, block: Block) -> bool:
  """The message's (view, seq, block_hash) are exactly those the block commits to."""
  return (
    message.block_hash == block.block_hash
    and message.seq == block.index
    and dict(block.sealed_consensus) == {"view_number": message.view}
  )


def _counter(value: object, name: str) -> int:
  if type(value) is not int or not 0 <= value < MAX_COUNTER:
    raise MalformedMessage(f"{name} must be a non-negative integer")
  return value


def _text(value: object, pattern: re.Pattern[str], name: str) -> str:
  if not isinstance(value, str) or not pattern.fullmatch(value):
    raise MalformedMessage(f"{name} is malformed")
  return value


def decode_message(raw: dict[str, Any]) -> PbftMessage:
  """Strict decode; any missing, extra or ill-typed field raises `MalformedMessage`."""
  kind = raw.get("type")
  if kind not in MESSAGE_TYPES:
    raise MalformedMessage("unknown PBFT message type")
  expected = {"type", "view", "seq", "block_hash", "node_id", "signature"}
  if kind == PRE_PREPARE:
    expected.add("block")
  if set(raw) != expected:
    raise MalformedMessage("unexpected or missing fields")
  block = raw.get("block")
  if kind == PRE_PREPARE and not isinstance(block, dict):
    raise MalformedMessage("pre-prepare must carry a block object")
  return PbftMessage(
    kind=kind,
    view=_counter(raw["view"], "view"),
    seq=_counter(raw["seq"], "seq"),
    block_hash=_text(raw["block_hash"], _HASH_RE, "block_hash"),
    node_id=_text(raw["node_id"], _ID_RE, "node_id"),
    signature=_text(raw["signature"], _SIG_RE, "signature"),
    block=block,
  )
