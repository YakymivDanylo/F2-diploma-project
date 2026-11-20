"""PBFT round state and the pure vote-counting rules (UC-6 steps 3-5).

`Round` holds the votes of one `(view, seq)`, `Lock` the block this node prepared and its
certificate. The helpers here are pure: they read a round and the inputs they are handed
(members, a key resolver) and never touch the network, the chain or the engine's other state,
so the counting rules can be read - and tested - on their own. `PbftEngine` keeps thin
wrappers (`prepare_votes`, `commit_votes`) around them.
"""

from __future__ import annotations

from collections.abc import Callable, Collection
from dataclasses import dataclass, field
from typing import Any

from blockchain_core import Block, commit_payload, public_key_to_pem, verify_canonical
from blockchain_core.keys import PublicKey
from node.consensus.pbft.messages import Kind, PreparedCert


def key_id(key: PublicKey) -> bytes:
  """One identity per key: two members sharing a key count once."""
  return public_key_to_pem(key)


@dataclass(frozen=True)
class Lock:
  """This node prepared `block` at `cert.seq`, proven by `cert`."""

  cert: PreparedCert
  block: Block


@dataclass
class Round:
  """Votes for one `(view, seq)`. At most ONE vote per member per phase is ever counted."""

  view: int
  seq: int
  candidate: Block | None = None  # the locked-in pre-prepared block, once screened as valid
  primary: str | None = None  # who pre-prepared it (= primary_of(view)): its implicit prepare
  pre_prepare_signature: str | None = None
  rejected: set[str] = field(default_factory=set)  # candidate hashes that failed screening
  prepares: dict[str, tuple[str, str]] = field(default_factory=dict)  # node -> (hash, sig)
  commits: dict[str, tuple[str, str]] = field(default_factory=dict)  # node -> (hash, sig)
  verified_commits: dict[str, bool] = field(default_factory=dict)  # node_id -> signature ok
  conflicts: list[tuple[Kind, str, str, str]] = field(default_factory=list)  # evidence
  conflicted: set[tuple[Kind, str]] = field(default_factory=set)  # bounds `conflicts`
  prepared: bool = False
  finalizing: bool = False
  failed_votes: frozenset[str] | None = None  # a vote set whose block `ChainState` refused
  outbox: list[dict[str, Any]] = field(default_factory=list)  # our own messages, for resend
  started_wall: int = 0
  opened_at: float | None = None  # monotonic time of the first activity (round timeout)


def count_prepare_votes(current: Round, members: Collection[str]) -> int:
  """Distinct members that prepared the candidate. Counting rule (UC-6 step 3, closes M-7):
  the primary's pre-prepare IS its prepare vote - it is counted here once, implicitly - and
  the primary never sends (and we never count) a separate prepare message from it."""
  if current.candidate is None:
    return 0
  target = current.candidate.block_hash
  primary = current.primary  # the pre-prepare's sender, frozen when the candidate locked in
  explicit = sum(
    1
    for node_id, (voted, _sig) in current.prepares.items()
    if voted == target and node_id != primary and node_id in members
  )
  return 1 + explicit


def build_certificate(current: Round) -> PreparedCert:
  """The prepared certificate of a round with a candidate: the primary's pre-prepare
  signature plus every matching prepare from another node, sorted by node id."""
  assert current.candidate is not None and current.pre_prepare_signature is not None
  target = current.candidate.block_hash
  return PreparedCert(
    view=current.view,
    seq=current.seq,
    block_hash=target,
    primary_signature=current.pre_prepare_signature,
    prepares=tuple(
      sorted(
        (node_id, sig)
        for node_id, (voted, sig) in current.prepares.items()
        if voted == target and node_id != current.primary
      )
    ),
  )


def verified_commit_votes(
  current: Round,
  members: Collection[str],
  resolve_key: Callable[[str, int], PublicKey | None],
  *,
  on_bad_signature: Callable[[str], None] = lambda _node_id: None,
) -> dict[str, str]:
  """Matching, valid commit votes by member - one per member AND per key, verified with the
  key in force at the candidate's timestamp (`resolve_key(node_id, at_ms)`), the same rule
  the core's quorum check applies. Counted only once the round is prepared: a commit received
  earlier is held, never acted on, so commits alone can never finalize a block (phase
  ordering, UC-6-E3). Each signature is checked once (memoized in `current.verified_commits`);
  a bad one is reported through `on_bad_signature` once."""
  candidate = current.candidate
  if candidate is None or not current.prepared:
    return {}
  payload = commit_payload(candidate.block_hash)
  counted: dict[str, str] = {}
  keys: set[bytes] = set()
  for node_id, (voted, signature) in sorted(current.commits.items()):
    if voted != candidate.block_hash or node_id not in members:
      continue
    key = resolve_key(node_id, candidate.timestamp)
    if key is None:
      continue
    fingerprint = key_id(key)
    if fingerprint in keys:
      continue
    ok = current.verified_commits.get(node_id)
    if ok is None:
      ok = current.verified_commits[node_id] = verify_canonical(key, payload, signature)
      if not ok:
        on_bad_signature(node_id)
    if ok:
      counted[node_id] = signature
      keys.add(fingerprint)
  return counted
