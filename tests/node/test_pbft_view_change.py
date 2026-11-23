"""Slice 18: PBFT view change (UC-6-D; QA TC-6.7, TC-6.10, TC-6.12, TC-6.13, TC-12.5).

Unit tests for the pure `ViewChangeState` and the message / certificate / state-store layers, then
cluster tests. Cluster tests set `PBFT_ROUND_TIMEOUT_S` BEFORE building the cluster; injection
tests that must not be disturbed by a round timeout use a long one so only the trigger under test
can start a view change.
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

import pytest
from chain_factory import pbft_chain
from network_helpers import Cluster, until
from node_helpers import NodeEnv
from pbft_helpers import (
  IDS,
  drain,
  feed,
  propose,
  record_sends,
  rehash,
  resign,
  sent_of,
  signed_candidate,
  vote,
)
from sync_helpers import run

from blockchain_core import (
  Block,
  public_key_to_pem,
  sign_commit,
)
from blockchain_core.storage.chain_store import block_to_dict
from node.config import ConfigError, load_config
from node.consensus.pbft import view_change as view_change_module
from node.consensus.pbft.engine import PbftEngine
from node.consensus.pbft.messages import (
  COMMIT,
  NEW_VIEW,
  NO_BLOCK,
  PRE_PREPARE,
  PREPARE,
  VIEW_CHANGE,
  MalformedMessage,
  PbftMessage,
  PreparedCert,
  Vote,
  decode_cert,
  decode_message,
  make_message,
  matches_block,
  sign_vote,
  verify_cert,
  verify_message,
  verify_vote,
)
from node.consensus.pbft.state_store import (
  PbftState,
  PbftStateError,
  PbftStateStore,
  state_path_for,
)
from node.consensus.pbft.view_change import MAX_VIEWS_AHEAD, ViewChangeState

H1, H2, H3 = "1" * 64, "2" * 64, "3" * 64


def _cluster(node_env: NodeEnv, ids: tuple[str, ...] = IDS, *, timeout: str = "0.3") -> Cluster:
  node_env.env["PBFT_ROUND_TIMEOUT_S"] = timeout
  return Cluster(node_env, ids=ids, mode="pbft")


def primary_of(view: int) -> str:
  return IDS[view % len(IDS)]


def vc_vote(
  env: NodeEnv,
  node_id: str,
  view: int,
  *,
  seq: int = 1,
  block: Block | None = None,
  cert: PreparedCert | None = None,
) -> PbftMessage:
  """A signed view-change vote (NO_BLOCK unless it names a locked `block` and its `cert`)."""
  return make_message(
    VIEW_CHANGE,
    env.validator_keys[node_id].private_key,
    view=view,
    seq=seq,
    block_hash=NO_BLOCK if block is None else block.block_hash,
    node_id=node_id,
    block=None if block is None else block_to_dict(block),
    cert=cert,
  )


def make_cert(
  env: NodeEnv, block: Block, view: int, preparers: tuple[str, ...] = ("node3", "node4")
) -> PreparedCert:
  """A genuine prepared certificate: the view's primary's pre-prepare plus prepares."""
  primary = primary_of(view)
  key = env.validator_keys[primary].private_key
  pre = sign_vote(
    PRE_PREPARE, key, view=view, seq=block.index, block_hash=block.block_hash, node_id=primary
  )
  prepares = tuple(
    sorted(
      (
        node,
        sign_vote(
          PREPARE,
          env.validator_keys[node].private_key,
          view=view,
          seq=block.index,
          block_hash=block.block_hash,
          node_id=node,
        ),
      )
      for node in preparers
    )
  )
  return PreparedCert(view, block.index, block.block_hash, pre, prepares)


def pre_prepare(
  env: NodeEnv, sender: str, block: Block, view: int, cert: PreparedCert | None = None
) -> PbftMessage:
  return make_message(
    PRE_PREPARE,
    env.validator_keys[sender].private_key,
    view=view,
    seq=block.index,
    block_hash=block.block_hash,
    node_id=sender,
    block=block_to_dict(block),
    cert=cert,
  )


def drop_messages(node, kinds: set[str], *, view: int | None = None) -> None:
  """Make `node` silently lose its own outgoing messages of `kinds` (optionally of one view)."""
  original = node.manager.broadcast

  async def filtered(message, *, only=None):
    if message.get("type") in kinds and (view is None or message.get("view") == view):
      return None
    return await original(message, only=only)

  node.manager.broadcast = filtered


def plain_vote(node: str, view: int, seq: int = 1, block_hash: str = NO_BLOCK) -> PbftMessage:
  return PbftMessage(VIEW_CHANGE, view, seq, block_hash, node, "aa")


# =================================================================== ViewChangeState rules


def _state(**kwargs) -> ViewChangeState:
  return ViewChangeState(self_id="node2", quorum=3, f=1, **kwargs)


def test_accept_new_duplicate_and_stale() -> None:
  state = _state(view=2)
  assert state.accept(plain_vote("node3", 2)).kind == "stale"  # not above the current view
  assert state.accept(plain_vote("node3", 1)).kind == "stale"
  assert state.accept(plain_vote("node3", 3)).kind == "new"
  assert state.accept(plain_vote("node3", 3)).kind == "duplicate"
  assert state.accept(plain_vote("node3", 4)).kind == "new"  # the latest (highest) vote wins
  assert state.latest["node3"].view == 4
  assert state.accept(plain_vote("node3", 3)).kind == "stale"  # never goes back down
  assert state.latest["node3"].view == 4


def test_accept_bounds_views_ahead() -> None:
  state = _state(view=1)
  assert state.accept(plain_vote("node3", 1 + MAX_VIEWS_AHEAD)).kind == "new"
  assert state.accept(plain_vote("node4", 1 + MAX_VIEWS_AHEAD + 1)).kind == "stale"
  assert "node4" not in state.latest  # bounded state: far-future votes are not kept


def test_conflict_only_for_two_different_locks_at_one_view_and_seq() -> None:
  state = _state()
  assert state.accept(plain_vote("node3", 2, 1, H1)).kind == "new"
  outcome = state.accept(plain_vote("node3", 2, 1, H2))
  assert outcome.kind == "conflict" and outcome.previous is not None
  assert outcome.previous.block_hash == H1
  assert state.latest["node3"].block_hash == H1  # the first stays on record


@pytest.mark.parametrize(
  ("first", "second"),
  [
    ((2, 1, NO_BLOCK), (2, 1, H1)),  # a lock gained after a NO_BLOCK vote
    ((2, 1, H1), (2, 1, NO_BLOCK)),  # NO_BLOCK never names a block, so no conflict
    ((2, 1, H1), (2, 2, H2)),  # the tip moved: another seq
    ((2, 1, H1), (3, 1, H2)),  # a higher view always replaces
  ],
)
def test_honest_updates_are_not_conflicts(first, second) -> None:
  state = _state()
  assert state.accept(plain_vote("node3", *first)).kind == "new"
  assert state.accept(plain_vote("node3", *second)).kind == "new"


def test_join_target_needs_f_plus_one_other_members() -> None:
  state = _state()
  assert state.join_target() is None
  state.accept(plain_vote("node3", 3))
  assert state.join_target() is None  # one Byzantine member alone cannot pull us along
  state.accept(plain_vote("node4", 5))
  assert state.join_target() == 3  # the (f+1)-th highest: at least one honest node wants it
  state.accept(plain_vote("node1", 9))
  assert state.join_target() == 5  # wanted = [9, 5, 3] -> index f = 1


def test_join_target_ignores_self_and_already_reached_targets() -> None:
  state = _state()
  state.accept(plain_vote("node2", 4))  # our own vote never counts towards joining
  state.accept(plain_vote("node3", 4))
  assert state.join_target() is None
  state.accept(plain_vote("node4", 4))
  assert state.join_target() == 4
  state.start(4)
  assert state.join_target() is None  # already voting for it
  state.accept(plain_vote("node1", 6))
  state.accept(plain_vote("node3", 6))
  assert state.join_target() == 6  # only a HIGHER target re-triggers


def test_installable_is_the_highest_view_with_a_quorum_behind_it() -> None:
  state = _state()
  assert state.installable() is None
  state.accept(plain_vote("node2", 1))
  state.accept(plain_vote("node3", 1))
  assert state.installable() is None  # 2 of 3
  state.accept(plain_vote("node4", 1))
  assert state.installable() == 1
  state.accept(plain_vote("node3", 4))
  state.accept(plain_vote("node4", 3))
  assert state.installable() == 1  # views [4, 3, 1]: only 1 has three supporters
  state.accept(plain_vote("node2", 3))
  assert state.installable() == 3  # views [4, 3, 3]: a vote for a higher view supports lower


def test_install_moves_view_and_keeps_only_higher_votes() -> None:
  state = _state()
  for node in ("node2", "node3", "node4"):
    state.accept(plain_vote(node, 2))
  state.accept(plain_vote("node1", 5))
  state.start(2)
  state.attempts = 3
  supporting = state.install(2)
  assert {v.node_id for v in supporting} == {"node1", "node2", "node3", "node4"}
  assert state.view == 2 and state.target is None and state.attempts == 0
  assert set(state.latest) == {"node1"}  # only the vote for a view above the installed one
  assert {v.node_id for v in state.install_votes} == {"node1", "node2", "node3", "node4"}
  assert all(isinstance(v, Vote) for v in state.install_votes)


def test_adopt_only_moves_forward_and_prunes() -> None:
  state = _state(view=1)
  state.accept(plain_vote("node3", 3))
  state.accept(plain_vote("node4", 6))
  state.start(3)
  assert not state.adopt(1) and not state.adopt(0)
  assert state.adopt(3)
  assert state.view == 3 and state.target is None  # our own target was reached
  assert set(state.latest) == {"node4"}
  state.start(8)
  assert state.adopt(5)
  assert state.target == 8  # a target above the adopted view stays open


def test_accept_install_votes_counts_distinct_members_at_or_above_the_view() -> None:
  state = _state()
  votes = [
    Vote(3, 1, NO_BLOCK, "node1", "aa"),
    Vote(3, 1, NO_BLOCK, "node1", "bb"),  # the same member twice
    Vote(4, 1, NO_BLOCK, "node3", "aa"),
    Vote(2, 1, NO_BLOCK, "node4", "aa"),  # below the proven view
  ]
  assert not state.accept_install_votes(votes, 3)
  votes.append(Vote(3, 1, NO_BLOCK, "node4", "aa"))
  assert state.accept_install_votes(votes, 3)


def test_start_and_cancel_reset_the_attempt_counter() -> None:
  state = _state()
  state.start(2)
  state.attempts = 5
  assert state.in_progress
  state.start(3)
  assert state.attempts == 0 and state.target == 3
  state.cancel()
  assert not state.in_progress and state.attempts == 0


def test_view_change_documents_the_missing_state_transfer() -> None:  # TC-6.12
  doc = view_change_module.__doc__ or ""
  assert "NOT implemented" in doc
  for phrase in ("state transfer", "checkpoints", "watermarks"):
    assert phrase in doc


# ========================================================= messages: decode, certificates


def test_view_change_decode_round_trip_for_both_shapes(node_env: NodeEnv) -> None:
  empty = vc_vote(node_env, "node3", 2)
  assert decode_message(empty.to_wire()) == empty
  assert empty.to_wire()["block"] is None and empty.to_wire()["cert"] is None
  block = signed_candidate(node_env, 1)
  locked = vc_vote(node_env, "node3", 2, block=block, cert=make_cert(node_env, block, 0))
  decoded = decode_message(json.loads(json.dumps(locked.to_wire())))  # through real JSON
  assert decoded.cert == locked.cert and decoded.block_hash == block.block_hash
  assert decoded.block == block_to_dict(block)


def test_view_change_must_carry_block_and_cert_exactly_when_locked(node_env: NodeEnv) -> None:
  block = signed_candidate(node_env, 1)
  cert = make_cert(node_env, block, 0)
  locked = vc_vote(node_env, "node3", 2, block=block, cert=cert).to_wire()
  for broken in (
    {**locked, "block": None},  # names a block but ships none
    {**locked, "cert": None},  # names a block but ships no certificate
    {k: v for k, v in locked.items() if k != "cert"},  # missing field
    {**locked, "block_hash": NO_BLOCK},  # claims NO_BLOCK but ships a lock
    {**locked, "extra": 1},
  ):
    with pytest.raises(MalformedMessage):
      decode_message(broken)
  empty = vc_vote(node_env, "node3", 2).to_wire()
  with pytest.raises(MalformedMessage):
    decode_message({**empty, "block": locked["block"]})
  with pytest.raises(MalformedMessage):
    decode_message({**empty, "cert": locked["cert"]})


def test_new_view_decode_round_trip_and_bounds(node_env: NodeEnv) -> None:
  votes = tuple(vc_vote(node_env, node, 2).vote() for node in ("node1", "node3", "node4"))
  message = make_message(
    NEW_VIEW,
    node_env.validator_keys["node2"].private_key,
    view=2,
    seq=1,
    block_hash=NO_BLOCK,
    node_id="node2",
    votes=votes,
  )
  decoded = decode_message(json.loads(json.dumps(message.to_wire())))
  assert decoded == message and decoded.votes == votes
  wire = message.to_wire()
  for broken in (
    {**wire, "votes": []},  # must be non-empty
    {**wire, "votes": "x"},
    {**wire, "votes": [wire["votes"][0]] * 65},  # bounded by MAX_VOTES
    {**wire, "votes": [{**wire["votes"][0], "extra": 1}]},
    {**wire, "votes": [{**wire["votes"][0], "signature": "zz"}]},
    {k: v for k, v in wire.items() if k != "votes"},
  ):
    with pytest.raises(MalformedMessage):
      decode_message(broken)


def test_pre_prepare_cert_is_optional_but_must_be_well_formed(node_env: NodeEnv) -> None:
  block = signed_candidate(node_env, 1, proposer="node2", view=1)
  cert = make_cert(node_env, block, 1)
  plain = pre_prepare(node_env, "node3", block, 2)
  assert "cert" not in plain.to_wire() and decode_message(plain.to_wire()).cert is None
  carried = pre_prepare(node_env, "node3", block, 2, cert)
  assert decode_message(json.loads(json.dumps(carried.to_wire()))).cert == cert
  with pytest.raises(MalformedMessage):
    decode_message({**carried.to_wire(), "cert": None})
  with pytest.raises(MalformedMessage):
    decode_message({**carried.to_wire(), "cert": {**cert.to_wire(), "extra": 1}})
  with pytest.raises(MalformedMessage):  # a prepare never carries a cert
    decode_message({**vote(node_env, PREPARE, "node3", block).to_wire(), "cert": cert.to_wire()})


def test_decode_cert_rejects_malformed_certificates(node_env: NodeEnv) -> None:
  block = signed_candidate(node_env, 1)
  wire = make_cert(node_env, block, 0).to_wire()
  assert decode_cert(wire).prepares == tuple(sorted(decode_cert(wire).prepares))
  for broken in (
    {**wire, "view": -1},
    {**wire, "view": True},
    {**wire, "seq": "1"},
    {**wire, "block_hash": "xyz"},
    {**wire, "primary_signature": ""},  # the primary's signature is required
    {**wire, "prepares": "none"},
    {**wire, "prepares": [{"node_id": "node3"}]},
    {**wire, "prepares": [{"node_id": "bad id!", "signature": "aa"}]},
    {**wire, "prepares": [{"node_id": "node3", "signature": "aa"}] * 65},
    {k: v for k, v in wire.items() if k != "prepares"},
    None,
    [],
  ):
    with pytest.raises(MalformedMessage):
      decode_cert(broken)


def _verify(env: NodeEnv, cert: PreparedCert, *, quorum: int = 3, members=frozenset(IDS)) -> bool:
  return verify_cert(
    cert,
    primary_of=lambda view: primary_of(view),
    members=members,
    quorum=quorum,
    resolve_key=lambda node_id: (
      env.validator_keys[node_id].public_key if node_id in env.validator_keys else None
    ),
    key_id=public_key_to_pem,
  )


def test_verify_cert_accepts_a_quorum_and_rejects_too_few(node_env: NodeEnv) -> None:
  block = signed_candidate(node_env, 1)
  assert _verify(node_env, make_cert(node_env, block, 0))
  assert _verify(node_env, make_cert(node_env, block, 0, ("node2", "node3", "node4")))
  assert not _verify(node_env, make_cert(node_env, block, 0, ("node3",)))  # primary + 1 < 3
  assert not _verify(node_env, make_cert(node_env, block, 0, ()))


def test_verify_cert_does_not_double_count_a_signer(node_env: NodeEnv) -> None:
  block = signed_candidate(node_env, 1)
  cert = make_cert(node_env, block, 0, ("node3",))
  doubled = PreparedCert(
    cert.view, cert.seq, cert.block_hash, cert.primary_signature, cert.prepares * 2
  )
  assert not _verify(node_env, doubled)  # the same prepare twice is still one signer
  full = make_cert(node_env, block, 0, ("node3", "node4"))
  primary_prepare = (
    "node1",
    sign_vote(
      PREPARE,
      node_env.validator_keys["node1"].private_key,
      view=0,
      seq=1,
      block_hash=block.block_hash,
      node_id="node1",
    ),
  )
  padded = PreparedCert(
    0, 1, block.block_hash, full.primary_signature, (primary_prepare, full.prepares[0])
  )
  assert not _verify(node_env, padded)  # the primary's own prepare adds nothing


def test_verify_cert_rejects_a_bad_primary_signature(node_env: NodeEnv) -> None:
  block = signed_candidate(node_env, 1)
  cert = make_cert(node_env, block, 0)
  wrong_primary = make_cert(node_env, block, 1)  # signed by node2, claimed for view 0
  forged = PreparedCert(0, 1, block.block_hash, wrong_primary.primary_signature, cert.prepares)
  assert not _verify(node_env, forged)
  other_hash = PreparedCert(0, 1, H1, cert.primary_signature, cert.prepares)
  assert not _verify(node_env, other_hash)  # signatures are bound to the block hash
  other_seq = PreparedCert(0, 2, block.block_hash, cert.primary_signature, cert.prepares)
  assert not _verify(node_env, other_seq)
  as_prepare = PreparedCert(  # a prepare signature cannot stand in for the pre-prepare
    0,
    1,
    block.block_hash,
    sign_vote(
      PREPARE,
      node_env.validator_keys["node1"].private_key,
      view=0,
      seq=1,
      block_hash=block.block_hash,
      node_id="node1",
    ),
    cert.prepares,
  )
  assert not _verify(node_env, as_prepare)


def test_verify_cert_ignores_non_member_and_forged_prepares(node_env: NodeEnv) -> None:
  block = signed_candidate(node_env, 1)
  cert = make_cert(node_env, block, 0, ("node3",))
  stranger_key = node_env.validator_keys["node4"].private_key
  stranger = (  # a valid signature, but "node9" is not a ValidatorSet member
    "node9",
    sign_vote(PREPARE, stranger_key, view=0, seq=1, block_hash=block.block_hash, node_id="node9"),
  )
  with_stranger = PreparedCert(
    0, 1, block.block_hash, cert.primary_signature, (*cert.prepares, stranger)
  )
  assert not _verify(node_env, with_stranger)  # primary + node3 only
  members3 = frozenset({"node1", "node2", "node3"})
  assert not _verify(node_env, make_cert(node_env, block, 0, ("node3", "node4")), members=members3)
  framed = (  # node4's name on node3's signature
    "node4",
    cert.prepares[0][1],
  )
  assert not _verify(
    node_env,
    PreparedCert(0, 1, block.block_hash, cert.primary_signature, (*cert.prepares, framed)),
  )
  no_primary = verify_cert(
    make_cert(node_env, block, 0),
    primary_of=lambda _view: None,
    members=frozenset(IDS),
    quorum=3,
    resolve_key=lambda n: node_env.validator_keys[n].public_key,
    key_id=public_key_to_pem,
  )
  assert not no_primary  # fail closed without a primary


def test_verify_cert_unknown_key_fails_closed(node_env: NodeEnv) -> None:
  block = signed_candidate(node_env, 1)
  cert = make_cert(node_env, block, 0)
  assert not verify_cert(
    cert,
    primary_of=primary_of,
    members=frozenset(IDS),
    quorum=3,
    resolve_key=lambda _node: None,
    key_id=public_key_to_pem,
  )


def test_view_change_signature_is_bound_to_view_seq_hash_and_domain(node_env: NodeEnv) -> None:
  key = node_env.validator_keys["node3"]
  message = vc_vote(node_env, "node3", 2)
  assert verify_message(message, key.public_key) and verify_vote(message.vote(), key.public_key)
  for forged in (
    PbftMessage(VIEW_CHANGE, 3, 1, NO_BLOCK, "node3", message.signature),
    PbftMessage(VIEW_CHANGE, 2, 2, NO_BLOCK, "node3", message.signature),
    PbftMessage(VIEW_CHANGE, 2, 1, H1, "node3", message.signature),
    PbftMessage(VIEW_CHANGE, 2, 1, NO_BLOCK, "node4", message.signature),
    PbftMessage(PREPARE, 2, 1, NO_BLOCK, "node3", message.signature),  # replayed as a prepare
    PbftMessage(NEW_VIEW, 2, 1, NO_BLOCK, "node3", message.signature),
    PbftMessage(COMMIT, 2, 1, NO_BLOCK, "node3", message.signature),
  ):
    assert not verify_message(forged, key.public_key)


def test_matches_block_is_relaxed_for_carried_blocks_only(node_env: NodeEnv) -> None:
  block = signed_candidate(node_env, 1, proposer="node2", view=1)
  assert matches_block(pre_prepare(node_env, "node3", block, 1), block)  # fresh
  assert matches_block(pre_prepare(node_env, "node4", block, 3), block)  # carried into view 3
  assert not matches_block(pre_prepare(node_env, "node1", block, 0), block)  # from the future
  wrong_hash = make_message(
    PRE_PREPARE,
    node_env.validator_keys["node3"].private_key,
    view=1,
    seq=1,
    block_hash=H1,
    node_id="node3",
    block=block_to_dict(block),
  )
  assert not matches_block(wrong_hash, block)
  wrong_seq = make_message(
    PRE_PREPARE,
    node_env.validator_keys["node3"].private_key,
    view=1,
    seq=2,
    block_hash=block.block_hash,
    node_id="node3",
    block=block_to_dict(block),
  )
  assert not matches_block(wrong_seq, block)
  unsealed = rehash(block, sealed_consensus={"nonce": 1})
  assert not matches_block(pre_prepare(node_env, "node3", unsealed, 1), unsealed)


# ============================================================================ state store


def _state_with_lock() -> PbftState:
  return PbftState(
    view=3,
    signed={(0, 1): H1, (2, 5): H2},
    lock={"cert": {"view": 0}, "block": {"index": 1}},
  )


def test_state_store_round_trip(tmp_path: Path) -> None:
  store = PbftStateStore(tmp_path / "chain.json.pbft-state.json")
  assert store.load() == PbftState()  # a missing file is an empty state
  store.save(_state_with_lock())
  loaded = PbftStateStore(store.path).load()  # a fresh store: really read from disk
  assert loaded == _state_with_lock()
  assert isinstance(next(iter(loaded.signed)), tuple)
  store.save(PbftState(view=4))
  assert store.load() == PbftState(view=4)  # overwritten atomically, lock cleared


def test_state_store_leaves_no_temp_files_and_survives_repeated_saves(tmp_path: Path) -> None:
  store = PbftStateStore(tmp_path / "state.json")
  for view in range(5):
    store.save(PbftState(view=view, signed={(view, 1): H1}))
  assert sorted(p.name for p in tmp_path.iterdir()) == ["state.json"]
  assert json.loads(store.path.read_text())["view"] == 4


@pytest.mark.parametrize(
  "content",
  [
    "{not json",
    "[]",
    json.dumps({"version": 99, "view": 0, "signed": [], "lock": None}),
    json.dumps({"version": 1, "view": 0, "signed": [[0, 1]], "lock": None}),
    json.dumps({"version": 1, "view": "x", "signed": [], "lock": None}),
    json.dumps({"version": 1, "view": 0, "signed": [], "lock": "no"}),
    json.dumps({"version": 1, "signed": [], "lock": None}),
  ],
)
def test_state_store_fails_closed_on_unreadable_state(tmp_path: Path, content: str) -> None:
  path = tmp_path / "state.json"
  path.write_text(content, encoding="utf-8")
  with pytest.raises(PbftStateError):
    PbftStateStore(path).load()


def test_state_path_sits_next_to_the_chain_file(tmp_path: Path) -> None:
  chain = tmp_path / "data" / "chain.json"
  path = state_path_for(chain)
  assert path.parent == chain.parent and path != chain and "chain.json" in path.name


def test_round_timeout_is_configurable(node_env: NodeEnv) -> None:
  assert load_config({**node_env.env}).pbft_round_timeout_s == 5.0
  assert load_config({**node_env.env, "PBFT_ROUND_TIMEOUT_S": "0.3"}).pbft_round_timeout_s == 0.3
  for bad in ("0", "-1", "abc", "nan", "inf"):
    with pytest.raises(ConfigError):
      load_config({**node_env.env, "PBFT_ROUND_TIMEOUT_S": bad})


# ================================================================ TC-6.7 invalid proposal


def _bad_merkle(env: NodeEnv) -> Block:
  block = signed_candidate(env, 1)
  return resign(env, rehash(block, merkle_root="ab" * 32))


def _bad_record_signature(env: NodeEnv) -> Block:
  block = signed_candidate(env, 1)
  record = block.document_records[0]
  forged = type(record)(
    document_hash=record.document_hash,
    issuer_id=record.issuer_id,
    issued_at=record.issued_at,
    metadata={"seed": 666},  # changed after the issuer signed it
    ipfs_cid=record.ipfs_cid,
    signature=record.signature,
  )
  return resign(env, rehash(block, document_records=(forged,)))


@pytest.mark.parametrize("build", [_bad_merkle, _bad_record_signature])
def test_invalid_pre_prepare_triggers_an_immediate_view_change(
  node_env: NodeEnv, build
) -> None:  # TC-6.7
  bad = build(node_env)

  async def scenario() -> None:
    # A long round timeout: only the invalid proposal itself can start this view change.
    async with _cluster(node_env, timeout="60") as c:
      await c.all_connected()
      replicas = [c["node2"], c["node3"], c["node4"]]
      spies = {n.node_id: record_sends(n) for n in replicas}
      feed_to = [vote(node_env, PRE_PREPARE, "node1", bad)]
      for node in replicas:
        feed(node, *feed_to)
      await until(lambda: all(n.engine.view == 1 for n in c.nodes.values()), timeout=10)
      for node in replicas:
        prepares = [m for m in sent_of(spies[node.node_id], "pbft_prepare")]
        assert all(m["block_hash"] != bad.block_hash for m in prepares)  # no prepare for it
        votes = sent_of(spies[node.node_id], "pbft_view_change")
        assert votes and {m["view"] for m in votes} == {1}
        assert node.manager.flags.get("node1", 0) >= 1  # the primary is flagged
      for node in c.nodes.values():
        assert node.engine.primary_of(1) == "node2" and node.tip == 0
      # the new primary finalizes a valid record in view 1
      await propose(c["node2"], node_env, 7)
      await until(lambda: all(n.tip == 1 for n in c.nodes.values()), timeout=10)
      block = c["node3"].context.current_blocks()[1]
      assert block.proposer_id == "node2" and dict(block.sealed_consensus) == {"view_number": 1}
      assert block.block_hash != bad.block_hash
      assert len({n.context.current_blocks()[1].block_hash for n in c.nodes.values()}) == 1
      for node in c.nodes.values():
        assert node.context.validator.full(node.context.current_blocks()).valid

  run(scenario())


def test_one_invalid_pre_prepare_does_not_move_the_other_replicas(node_env: NodeEnv) -> None:
  bad = _bad_merkle(node_env)

  async def scenario() -> None:
    async with _cluster(node_env, timeout="60") as c:
      await c.all_connected()
      feed(c["node2"], vote(node_env, PRE_PREPARE, "node1", bad))
      await until(lambda: c["node2"].engine.view_change.in_progress)
      await asyncio.sleep(1.2)  # a resend tick or two
      # one voter is below the f+1 join rule: nobody follows a lone (possibly Byzantine) vote
      assert [n.engine.view for n in c.nodes.values()] == [0, 0, 0, 0]
      assert not c["node3"].engine.view_change.in_progress
      assert c["node2"].engine.view_change.target == 1

  run(scenario())


# ==================================================== TC-6.10 / TC-6.12 round timeout


def test_round_timeout_moves_to_view_1_with_the_next_primary(node_env: NodeEnv) -> None:
  async def scenario() -> None:  # TC-6.10 / TC-6.12
    async with _cluster(node_env) as c:
      await c.all_connected()
      for node in c.nodes.values():
        drop_messages(node, {PREPARE})  # no prepare ever arrives: 2f+1 is never reached
      spy = record_sends(c["node2"])
      await propose(c["node1"], node_env, 1)
      await until(lambda: all(n.engine.view == 1 for n in c.nodes.values()), timeout=15)
      assert all(n.tip == 0 for n in c.nodes.values())  # nothing was finalized meanwhile
      for node in c.nodes.values():
        # deterministic round-robin: primary = members[view mod n]
        assert node.engine.primary_of(1) == "node2" == node.engine.members()[1]
      votes = sent_of(spy, "pbft_view_change")
      assert votes and {m["view"] for m in votes} == {1}  # exactly one target: no storm
      await until(
        lambda: all(n.context.validity_cache.liveness == "healthy" for n in c.nodes.values())
      )
      assert c["node2"].engine.is_primary and not c["node1"].engine.is_primary
      assert c["node1"].engine.primary_status() == ("other", "node2")

  run(scenario())


def test_round_timeout_then_a_working_view_finalizes(node_env: NodeEnv) -> None:
  async def scenario() -> None:  # TC-6.10 / TC-6.12: lost prepares in view 0 only
    async with _cluster(node_env) as c:
      await c.all_connected()
      for node in c.nodes.values():
        drop_messages(node, {PREPARE}, view=0)
      await propose(c["node1"], node_env, 1)
      await until(lambda: all(n.engine.view == 1 for n in c.nodes.values()), timeout=15)
      await propose(c["node2"], node_env, 2)
      await until(lambda: all(n.tip == 1 for n in c.nodes.values()), timeout=15)
      block = c["node3"].context.current_blocks()[1]
      assert block.proposer_id == "node2" and dict(block.sealed_consensus) == {"view_number": 1}
      assert len({n.context.current_blocks()[1].block_hash for n in c.nodes.values()}) == 1
      for node in c.nodes.values():
        assert node.context.validator.full(node.context.current_blocks()).valid

  run(scenario())


def test_primary_unreachable_moves_to_view_1_on_an_idle_network(node_env: NodeEnv) -> None:
  async def scenario() -> None:  # the primary-link-down trigger (no round is open at all)
    async with _cluster(node_env) as c:
      await c.all_connected()
      await c.network.sever(c["node1"].address)
      others = [c["node2"], c["node3"], c["node4"]]
      await until(lambda: all(n.engine.view == 1 for n in others), timeout=10)
      assert all(n.tip == 0 for n in others)
      assert all(
        n.engine.primary_status() == ("other", "node2") or n.node_id == "node2" for n in others
      )
      assert c["node2"].engine.primary_status() == ("self", "node2")

  run(scenario())


# ======================================== primary crash after prepared: certified re-proposal


def test_new_primary_reproposes_the_prepared_block_with_its_original_hash(
  node_env: NodeEnv,
) -> None:
  async def scenario() -> None:
    async with _cluster(node_env) as c:
      await c.all_connected()
      for node in c.nodes.values():
        drop_messages(node, {COMMIT}, view=0)  # prepared everywhere, but nothing can finalize
      spy = record_sends(c["node2"])
      await propose(c["node1"], node_env, 1)
      await until(
        lambda: all(c[n].engine.lock is not None for n in ("node2", "node3", "node4")),
        timeout=10,
      )
      locked = c["node2"].engine.lock.block.block_hash
      assert all(c[n].engine.lock.block.block_hash == locked for n in ("node3", "node4"))
      assert c["node2"].engine.lock.cert.view == 0 and c["node2"].tip == 0
      await c.network.sever(c["node1"].address)  # the primary crashes
      live = [c["node2"], c["node3"], c["node4"]]
      await until(lambda: all(n.tip == 1 for n in live), timeout=15)
      for node in live:
        block = node.context.current_blocks()[1]
        assert block.block_hash == locked  # the same block, not a replacement
        assert block.proposer_id == "node1" and dict(block.sealed_consensus) == {"view_number": 0}
        assert node.engine.view == 1
        assert node.context.validator.full(node.context.current_blocks()).valid
      # the view-change votes carried the lock; the new primary justified the block with a cert
      votes = sent_of(spy, "pbft_view_change")
      assert votes and votes[0]["block_hash"] == locked and votes[0]["cert"]["view"] == 0
      carried = [m for m in sent_of(spy, "pbft_pre_prepare", 1) if m["view"] == 1]
      assert carried and {m["block_hash"] for m in carried} == {locked}
      assert carried[0]["cert"]["view"] == 0 and carried[0]["cert"]["block_hash"] == locked
      assert carried[0]["node_id"] == "node2"

  run(scenario())


def test_new_primary_ignores_its_mempool_while_a_certified_block_exists(
  node_env: NodeEnv,
) -> None:
  async def scenario() -> None:
    async with _cluster(node_env) as c:
      await c.all_connected()
      for node in c.nodes.values():
        drop_messages(node, {COMMIT}, view=0)
      await propose(c["node1"], node_env, 1)
      await until(
        lambda: all(c[n].engine.lock is not None for n in ("node2", "node3", "node4")),
        timeout=10,
      )
      locked = c["node3"].engine.lock.block.block_hash
      await propose(c["node2"], node_env, 2)  # node2 has its own, different pending record
      await c.network.sever(c["node1"].address)
      live = [c["node2"], c["node3"], c["node4"]]
      await until(lambda: all(n.tip == 1 for n in live), timeout=15)
      assert {n.context.current_blocks()[1].block_hash for n in live} == {locked}
      await until(lambda: all(n.tip == 2 for n in live), timeout=15)  # then its own record
      second = c["node4"].context.current_blocks()[2]
      assert second.proposer_id == "node2" and dict(second.sealed_consensus) == {"view_number": 1}

  run(scenario())


# ======================================================= locks: refuse another block


async def _locked_lone_node(c: Cluster, env: NodeEnv):
  """node2 prepared block A at view 0 (lock), then installed view 2 (primary node3)."""
  node = c["node2"]
  sent = record_sends(node)
  block_a = signed_candidate(env, 1)
  feed(node, vote(env, PRE_PREPARE, "node1", block_a), vote(env, PREPARE, "node3", block_a))
  await until(lambda: node.engine.lock is not None)
  assert node.engine.lock.block.block_hash == block_a.block_hash
  feed(node, vc_vote(env, "node3", 2), vc_vote(env, "node4", 2))
  await until(lambda: node.engine.view == 2)
  return node, sent, block_a


def test_locked_node_votes_for_view_change_carrying_its_lock(node_env: NodeEnv) -> None:
  async def scenario() -> None:
    async with _cluster(node_env, ("node2",), timeout="60") as c:
      node, sent, block_a = await _locked_lone_node(c, node_env)
      await until(lambda: any(m["view"] == 2 for m in sent_of(sent, "pbft_view_change")))
      votes = [m for m in sent_of(sent, "pbft_view_change") if m["view"] == 2]
      assert votes and votes[0]["block_hash"] == block_a.block_hash
      assert votes[0]["block"]["block_hash"] == block_a.block_hash
      assert votes[0]["cert"]["block_hash"] == block_a.block_hash and votes[0]["cert"]["view"] == 0
      message = decode_message(votes[0])  # and it is a well-formed, strictly decodable message
      assert verify_message(message, node_env.validator_keys["node2"].public_key)
      assert _verify(node_env, message.cert)
      assert node.engine.lock.block.block_hash == block_a.block_hash  # kept through the change

  run(scenario())


def test_locked_node_refuses_a_fresh_block_without_a_higher_cert(node_env: NodeEnv) -> None:
  async def scenario() -> None:
    async with _cluster(node_env, ("node2",), timeout="60") as c:
      node, sent, block_a = await _locked_lone_node(c, node_env)
      fresh = signed_candidate(node_env, 2, proposer="node3", view=2)
      feed(node, pre_prepare(node_env, "node3", fresh, 2))
      await drain(node)
      assert all(m["block_hash"] != fresh.block_hash for m in sent_of(sent, "pbft_prepare"))
      assert fresh.block_hash in node.engine.round(1).rejected
      assert node.engine.lock.block.block_hash == block_a.block_hash
      assert node.manager.flags.get("node3", 0) == 0  # not proof of a faulty primary

  run(scenario())


def test_locked_node_refuses_a_cert_of_the_same_view(node_env: NodeEnv) -> None:
  async def scenario() -> None:
    async with _cluster(node_env, ("node2",), timeout="60") as c:
      node, sent, block_a = await _locked_lone_node(c, node_env)
      other = signed_candidate(node_env, 3, proposer="node1", view=0)  # also "prepared" in view 0
      feed(node, pre_prepare(node_env, "node3", other, 2, make_cert(node_env, other, 0)))
      await drain(node)
      assert all(m["block_hash"] != other.block_hash for m in sent_of(sent, "pbft_prepare"))
      assert node.engine.lock.block.block_hash == block_a.block_hash

  run(scenario())


def test_locked_node_accepts_a_block_with_a_higher_view_cert(node_env: NodeEnv) -> None:
  async def scenario() -> None:
    async with _cluster(node_env, ("node2",), timeout="60") as c:
      node, sent, block_a = await _locked_lone_node(c, node_env)
      newer = signed_candidate(node_env, 2, proposer="node2", view=1)
      feed(node, pre_prepare(node_env, "node3", newer, 2, make_cert(node_env, newer, 1)))
      await until(
        lambda: any(m["block_hash"] == newer.block_hash for m in sent_of(sent, "pbft_prepare"))
      )
      prepare = [m for m in sent_of(sent, "pbft_prepare") if m["block_hash"] == newer.block_hash]
      assert prepare[0]["view"] == 2

  run(scenario())


def test_carried_block_with_a_forged_cert_is_rejected(node_env: NodeEnv) -> None:
  async def scenario() -> None:
    async with _cluster(node_env, ("node2",), timeout="60") as c:
      node = c["node2"]
      sent = record_sends(node)
      feed(node, vc_vote(node_env, "node3", 2), vc_vote(node_env, "node4", 2))
      await until(lambda: node.engine.view == 2)
      older = signed_candidate(node_env, 2, proposer="node2", view=1)
      good = make_cert(node_env, older, 1)
      cases = {
        "missing": None,
        "too_few": make_cert(node_env, older, 1, ("node3",)),
        "wrong_view": make_cert(node_env, older, 2),  # not strictly below the message's view
        "wrong_hash": PreparedCert(1, 1, H1, good.primary_signature, good.prepares),
      }
      for case, cert in cases.items():
        feed(node, pre_prepare(node_env, "node3", older, 2, cert))
        await drain(node)
        assert sent_of(sent, "pbft_prepare") == [], case
      # a fresh block must not carry a cert at all
      fresh = signed_candidate(node_env, 4, proposer="node3", view=2)
      feed(node, pre_prepare(node_env, "node3", fresh, 2, make_cert(node_env, fresh, 1)))
      await drain(node)
      assert sent_of(sent, "pbft_prepare") == []

  run(scenario())


# ======================================================= TC-6.13 successive failures


def test_two_successive_primary_failures_converge(node_env: NodeEnv) -> None:
  async def scenario() -> None:  # TC-6.13
    async with _cluster(node_env) as c:
      await c.all_connected()
      await c.network.sever(c["node1"].address)
      await until(
        lambda: all(c[n].engine.view == 1 for n in ("node2", "node3", "node4")), timeout=10
      )
      c.network.heal(c["node1"].address)
      await until(lambda: c["node1"].engine.view == 1, timeout=10)  # new-view proof
      await c.network.sever(c["node2"].address)  # the new primary fails too
      alive = [c["node1"], c["node3"], c["node4"]]
      await until(lambda: all(n.engine.view == 2 for n in alive), timeout=15)
      assert all(n.engine.primary_of(2) == "node3" for n in alive)
      await propose(c["node3"], node_env, 1)
      await until(lambda: all(n.tip == 1 for n in alive), timeout=15)
      block = c["node1"].context.current_blocks()[1]
      assert block.proposer_id == "node3" and dict(block.sealed_consensus) == {"view_number": 2}
      assert len({n.context.current_blocks()[1].block_hash for n in alive}) == 1
      assert c["node2"].engine.view == 1  # the severed node stays behind, it did not run away
      for node in alive:
        assert node.context.validator.full(node.context.current_blocks()).valid

  run(scenario())


def test_failure_without_a_quorum_is_reported_not_looped_silently(
  node_env: NodeEnv, caplog: pytest.LogCaptureFixture
) -> None:
  async def scenario() -> None:  # TC-6.13 / UC-6-EC2
    async with _cluster(node_env) as c:
      await c.all_connected()
      await c.network.sever(c["node3"].address)
      await c.network.sever(c["node4"].address)
      await propose(c["node1"], node_env, 1)  # a round that can never reach quorum
      first, second = c["node1"], c["node2"]
      await until(lambda: first.engine.view_change.in_progress, timeout=10)
      await until(
        lambda: first.engine.view_change.attempts >= 2 and second.engine.view_change.attempts >= 2,
        timeout=15,
      )
      target = first.engine.view_change.target
      assert target == 1 and second.engine.view_change.target == 1
      await asyncio.sleep(1.5)
      # never installed, never silently escalated to ever higher views by a lone timer
      assert first.engine.view == 0 and second.engine.view == 0
      assert first.engine.view_change.target == 1
      assert first.context.validity_cache.liveness == "crash_fault_quorum_loss"
      assert first.engine.primary_status() == ("none", None)
      assert first.tip == 0 and second.tip == 0
      # heal one member: a quorum is possible again and the stuck vote converges
      c.network.heal(c["node3"].address)
      await until(
        lambda: all(c[n].engine.view == 1 for n in ("node1", "node2", "node3")), timeout=15
      )
      await propose(c["node2"], node_env, 2)
      live = [c["node1"], c["node2"], c["node3"]]
      await until(lambda: all(n.tip == 1 for n in live), timeout=15)
      assert c["node2"].context.current_blocks()[1].proposer_id == "node2"

  with caplog.at_level(logging.WARNING, logger="node.pbft"):
    run(scenario())
  warnings = [r for r in caplog.records if "still open" in r.getMessage()]
  assert warnings, "a stuck view change must be logged, never silent"
  assert any(
    "re-send" in r.getMessage() and "responsive members" in r.getMessage() for r in warnings
  )
  assert any("requested" in r.getMessage() for r in caplog.records)


# ======================================================================= rejoin


def test_returning_old_primary_adopts_the_view_on_an_idle_network(node_env: NodeEnv) -> None:
  async def scenario() -> None:
    async with _cluster(node_env) as c:
      await c.all_connected()
      await c.network.sever(c["node1"].address)
      others = [c["node2"], c["node3"], c["node4"]]
      await until(lambda: all(n.engine.view == 1 for n in others), timeout=10)
      assert c["node1"].engine.view == 0  # it saw nothing: still the (isolated) primary of 0
      c.network.heal(c["node1"].address)
      await until(lambda: c["node1"].engine.view == 1, timeout=10)  # new-view proof, no blocks
      node1 = c["node1"]
      assert node1.tip == 0 and all(n.tip == 0 for n in others)
      assert len({v.node_id for v in node1.engine.view_change.install_votes}) >= 3
      assert all(v.view >= 1 for v in node1.engine.view_change.install_votes)
      await until(lambda: node1.engine.primary_status() == ("other", "node2"), timeout=5)
      assert not node1.engine.is_primary
      # and it works: the old primary no longer proposes, the new one does
      await propose(c["node1"], node_env, 1)
      await asyncio.sleep(0.5)
      assert all(n.tip == 0 for n in c.nodes.values())
      await propose(c["node2"], node_env, 2)
      await until(lambda: all(n.tip == 1 for n in c.nodes.values()), timeout=15)
      assert c["node1"].context.current_blocks()[1].proposer_id == "node2"

  run(scenario())


def test_new_view_with_too_few_votes_is_not_adopted(node_env: NodeEnv) -> None:
  async def scenario() -> None:
    async with _cluster(node_env, ("node2",), timeout="60") as c:
      node = c["node2"]
      votes = tuple(vc_vote(node_env, n, 3).vote() for n in ("node1", "node3"))  # 2 < quorum 3
      proof = make_message(
        NEW_VIEW,
        node_env.validator_keys["node4"].private_key,
        view=3,
        seq=1,
        block_hash=NO_BLOCK,
        node_id="node4",
        votes=votes,
      )
      feed(node, proof)
      await drain(node)
      assert node.engine.view == 0 and node.manager.flags.get("node4", 0) >= 1

  run(scenario())


def test_new_view_with_forged_votes_is_not_adopted(node_env: NodeEnv) -> None:
  async def scenario() -> None:
    async with _cluster(node_env, ("node2",), timeout="60") as c:
      node = c["node2"]
      real = [vc_vote(node_env, n, 3).vote() for n in ("node1", "node3")]
      framed = vc_vote(node_env, "node1", 3).vote()  # node4's name on node1's signature
      forged = Vote(3, 1, NO_BLOCK, "node4", framed.signature)
      stranger = Vote(3, 1, NO_BLOCK, "node9", framed.signature)
      # one proof per sender per resend period: each attempt comes from another member
      for sender, extra in (("node4", forged), ("node3", stranger)):
        proof = make_message(
          NEW_VIEW,
          node_env.validator_keys[sender].private_key,
          view=3,
          seq=1,
          block_hash=NO_BLOCK,
          node_id=sender,
          votes=(*real, extra),
        )
        feed(node, proof)
        await drain(node)
        assert node.engine.view == 0
      genuine = make_message(
        NEW_VIEW,
        node_env.validator_keys["node1"].private_key,
        view=3,
        seq=1,
        block_hash=NO_BLOCK,
        node_id="node1",
        votes=(*real, vc_vote(node_env, "node4", 3).vote()),
      )
      feed(node, genuine)
      await until(lambda: node.engine.view == 3)

  run(scenario())


def _view_block(env: NodeEnv, previous: Block, view: int, proposer: str) -> Block:
  from chain_factory import _candidate

  from blockchain_core import attach_proposer_signature

  block = attach_proposer_signature(
    _candidate(env, previous, 1, "pbft", {"view_number": view}, proposer),
    env.validator_keys[proposer].private_key,
  )
  commits = tuple(
    sign_commit(block, node_id, env.validator_keys[node_id])
    for node_id in ("node1", "node2", "node3")
  )
  from dataclasses import replace

  return replace(block, commit_signatures=commits)


def test_view_is_adopted_from_a_finalized_tip_block(node_env: NodeEnv) -> None:
  async def scenario() -> None:
    async with _cluster(node_env, ("node2",), timeout="60") as c:
      node = c["node2"]
      genesis = node.context.current_blocks()[0]
      block = _view_block(node_env, genesis, 3, primary_of(3))
      assert (await node.receiver.handle_block("node4", block_to_dict(block))).kind == "accept"
      await until(lambda: node.engine.view == 3)
      assert node.engine.primary_of(3) == "node4"
      assert not node.engine.view_change.in_progress

  run(scenario())


def test_engine_boots_into_the_view_of_the_chain_tip(node_env: NodeEnv) -> None:
  # a chain whose tip was sealed in view 2 (here: view 0 blocks only, so a stored view wins)
  async def scenario() -> None:
    async with _cluster(node_env, ("node2",), timeout="60") as c:
      node = c["node2"]
      block = _view_block(node_env, node.context.current_blocks()[0], 2, primary_of(2))
      assert await node.engine.on_inbound_block(block)
      await until(lambda: node.engine.view == 2)
      store = PbftStateStore(state_path_for(node.context.config.chain_path))
      engine = PbftEngine(node.context, send=_null_send, state_store=store, round_timeout_s=60)
      assert engine.view == 2  # a restarted engine starts at the tip's view, not at 0

  run(scenario())


async def _null_send(message, targets=None):
  return None


# ================================================================== persistence / restart


def _restarted(node, sent: list, *, timeout: float = 60) -> PbftEngine:
  async def send(message, targets=None):
    sent.append(message)

  return PbftEngine(
    node.context,
    send=send,
    state_store=PbftStateStore(state_path_for(node.context.config.chain_path)),
    round_timeout_s=timeout,
  )


def test_restart_never_signs_a_second_hash_for_a_signed_slot(node_env: NodeEnv) -> None:
  block_a = signed_candidate(node_env, 1)
  block_b = signed_candidate(node_env, 2)

  async def scenario() -> None:
    async with _cluster(node_env, ("node2",), timeout="60") as c:
      node = c["node2"]
      feed(node, vote(node_env, PRE_PREPARE, "node1", block_a))  # node2 prepares A, no lock yet
      await until(lambda: node.engine.round(1) and node.engine.round(1).candidate)
      path = state_path_for(node.context.config.chain_path)
      saved = json.loads(path.read_text())
      assert saved["signed"] == [[0, 1, block_a.block_hash]] and saved["lock"] is None
      await node.engine.stop()  # crash
      sent: list = []
      engine = _restarted(node, sent)
      assert engine.lock is None and engine.view == 0
      await engine.start()
      try:
        engine.submit(vote(node_env, PRE_PREPARE, "node1", block_b))  # an equivocating primary
        await until(lambda: not engine._inbox)
        await asyncio.sleep(0.1)
        assert [m for m in sent if m["type"] == PREPARE] == []  # refused: A was signed already
      finally:
        await engine.stop()

  run(scenario())


def test_restart_keeps_the_lock_and_still_refuses_another_block(node_env: NodeEnv) -> None:
  block_a = signed_candidate(node_env, 1)
  block_b = signed_candidate(node_env, 2)

  async def scenario() -> None:
    async with _cluster(node_env, ("node2",), timeout="60") as c:
      node = c["node2"]
      feed(
        node,
        vote(node_env, PRE_PREPARE, "node1", block_a),
        vote(node_env, PREPARE, "node3", block_a),
      )
      await until(lambda: node.engine.lock is not None)
      path = state_path_for(node.context.config.chain_path)
      await until(lambda: node.engine.round(1).prepared)  # the lock is saved before this
      assert json.loads(path.read_text())["lock"] is not None
      cert = node.engine.lock.cert
      await node.engine.stop()
      sent: list = []
      engine = _restarted(node, sent)
      assert engine.lock is not None and engine.lock.block.block_hash == block_a.block_hash
      assert engine.lock.cert == cert  # the very same certificate
      await engine.start()
      try:
        engine.submit(vote(node_env, PRE_PREPARE, "node1", block_b))
        await until(lambda: not engine._inbox)
        await asyncio.sleep(0.1)
        assert [m for m in sent if m["type"] == PREPARE] == []
        assert engine.lock.block.block_hash == block_a.block_hash
      finally:
        await engine.stop()

  run(scenario())


def test_restart_drops_a_lock_for_a_height_that_is_final(node_env: NodeEnv) -> None:
  block_a = signed_candidate(node_env, 1)

  async def scenario() -> None:
    async with _cluster(node_env, ("node2",), timeout="60") as c:
      node = c["node2"]
      feed(
        node,
        vote(node_env, PRE_PREPARE, "node1", block_a),
        vote(node_env, PREPARE, "node3", block_a),
      )
      await until(lambda: node.engine.lock is not None)
      await until(lambda: node.engine.round(1).prepared)  # the lock is saved before this
      await node.engine.stop()
      assert await node.context.chain_state.replace(
        pbft_chain(node_env, 1), node.context.validator.full
      )
      engine = _restarted(node, [])
      assert engine.lock is None  # that height is final now: the lock is moot

  run(scenario())


def test_restart_keeps_the_installed_view(node_env: NodeEnv) -> None:
  async def scenario() -> None:
    async with _cluster(node_env, ("node2",), timeout="60") as c:
      node = c["node2"]
      feed(node, vc_vote(node_env, "node3", 2), vc_vote(node_env, "node4", 2))
      await until(lambda: node.engine.view == 2)  # joined (f+1) and installed (quorum)
      path = state_path_for(node.context.config.chain_path)
      await asyncio.sleep(0.5)  # the save is awaited off-loop; do not race it with a reader
      assert json.loads(path.read_text())["view"] == 2
      await node.engine.stop()
      assert _restarted(node, []).view == 2

  run(scenario())


def test_unreadable_state_file_stops_the_engine_from_booting(node_env: NodeEnv) -> None:
  async def scenario() -> None:
    async with _cluster(node_env, ("node2",), timeout="60") as c:
      node = c["node2"]
      state_path_for(node.context.config.chain_path).write_text("{garbage", encoding="utf-8")
      with pytest.raises(PbftStateError):
        _restarted(node, [])

  run(scenario())
