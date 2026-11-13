"""Slice 17: PBFT message security - strict decode, signature domains, receipt rules, screening."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest
from chain_factory import _record, pbft_block
from network_helpers import Cluster, until
from node_helpers import NodeEnv
from pbft_helpers import (
  drain,
  feed,
  now_ms,
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
  CommitSignature,
  build_genesis_block,
  sign_commit,
  verify_canonical,
)
from blockchain_core.merkle import build_root
from node.consensus.pbft.messages import (
  COMMIT,
  PRE_PREPARE,
  PREPARE,
  MalformedMessage,
  PbftMessage,
  decode_message,
  verify_message,
)
from node.main import NodeContext
from node.network.ws_pbft import PbftReceiver, is_pbft_message

HASH = "ab" * 32
SIG = "cd" * 32


def _wire(kind: str = PREPARE, **over: Any) -> dict[str, Any]:
  wire: dict[str, Any] = {
    "type": kind,
    "view": 0,
    "seq": 1,
    "block_hash": HASH,
    "node_id": "node2",
    "signature": SIG,
  }
  if kind == PRE_PREPARE:
    wire["block"] = {"index": 1}
  wire.update(over)
  return wire


# ------------------------------------------------------------------- strict decode


@pytest.mark.parametrize("kind", [PRE_PREPARE, PREPARE, COMMIT])
def test_decode_accepts_the_exact_shape(kind: str) -> None:
  message = decode_message(_wire(kind))
  assert message.kind == kind and message.view == 0 and message.seq == 1
  assert message.to_wire()["type"] == kind


@pytest.mark.parametrize("kind", [PRE_PREPARE, PREPARE, COMMIT])
def test_decode_rejects_extra_field(kind: str) -> None:
  with pytest.raises(MalformedMessage):
    decode_message(_wire(kind, extra=1))


@pytest.mark.parametrize("field", ["type", "view", "seq", "block_hash", "node_id", "signature"])
@pytest.mark.parametrize("kind", [PRE_PREPARE, PREPARE, COMMIT])
def test_decode_rejects_missing_field(kind: str, field: str) -> None:
  wire = _wire(kind)
  del wire[field]
  with pytest.raises(MalformedMessage):
    decode_message(wire)


def test_decode_rejects_block_on_non_pre_prepare_and_missing_block() -> None:
  with pytest.raises(MalformedMessage):
    decode_message(_wire(PREPARE, block={"index": 1}))
  with pytest.raises(MalformedMessage):
    decode_message(_wire(COMMIT, block={"index": 1}))
  wire = _wire(PRE_PREPARE)
  del wire["block"]
  with pytest.raises(MalformedMessage):
    decode_message(wire)
  for bad in (None, "x", [], 5):
    with pytest.raises(MalformedMessage):
      decode_message(_wire(PRE_PREPARE, block=bad))


@pytest.mark.parametrize("field", ["view", "seq"])
@pytest.mark.parametrize("value", [True, False, 1.0, "1", None, -1, 2**53, [1]])
def test_decode_rejects_non_int_counters(field: str, value: Any) -> None:
  with pytest.raises(MalformedMessage):
    decode_message(_wire(**{field: value}))


@pytest.mark.parametrize(
  "value", ["", "AB" * 32, "ab" * 31, "ab" * 33, "zz" * 32, " " + "ab" * 31 + "a", 7, None]
)
def test_decode_rejects_bad_block_hash(value: Any) -> None:
  with pytest.raises(MalformedMessage):
    decode_message(_wire(block_hash=value))


@pytest.mark.parametrize("value", ["", "x", "ABCD", "abc", "gg", "ab" * 600, "cd\n", 5, None])
def test_decode_rejects_bad_signature_hex(value: Any) -> None:
  with pytest.raises(MalformedMessage):
    decode_message(_wire(signature=value))


@pytest.mark.parametrize("value", ["", "a b", "node/1", "x" * 65, "nöde", 3, None])
def test_decode_rejects_bad_node_id(value: Any) -> None:
  with pytest.raises(MalformedMessage):
    decode_message(_wire(node_id=value))


@pytest.mark.parametrize("value", [None, "", "pbft_other", "block", 1, "PBFT_PREPARE"])
def test_decode_rejects_unknown_type(value: Any) -> None:
  with pytest.raises(MalformedMessage):
    decode_message(_wire(type=value))


# ------------------------------------------------------------- signature domains


def test_signature_is_bound_to_its_kind(node_env: NodeEnv) -> None:
  block = signed_candidate(node_env, 1)
  key = node_env.validator_keys["node2"].public_key
  prepare = vote(node_env, PREPARE, "node2", block)
  commit = vote(node_env, COMMIT, "node2", block)
  pre_prepare = vote(node_env, PRE_PREPARE, "node2", block)
  for message in (prepare, commit, pre_prepare):
    assert verify_message(message, key)
  # a signature never verifies under another kind (domain separation)
  assert not verify_message(replace(prepare, kind=PRE_PREPARE), key)
  assert not verify_message(replace(prepare, kind=COMMIT), key)
  assert not verify_message(replace(pre_prepare, kind=PREPARE), key)
  assert not verify_message(replace(pre_prepare, kind=COMMIT), key)
  assert not verify_message(replace(commit, kind=PREPARE), key)
  assert not verify_message(replace(commit, kind=PRE_PREPARE), key)


def test_signature_binds_view_seq_hash_and_sender(node_env: NodeEnv) -> None:
  block = signed_candidate(node_env, 1)
  key = node_env.validator_keys["node2"].public_key
  prepare = vote(node_env, PREPARE, "node2", block)
  assert not verify_message(replace(prepare, view=1), key)
  assert not verify_message(replace(prepare, seq=2), key)
  assert not verify_message(replace(prepare, block_hash=HASH), key)
  assert not verify_message(replace(prepare, node_id="node3"), key)
  assert not verify_message(prepare, node_env.validator_keys["node3"].public_key)


def test_prepare_signature_is_not_a_proposer_signature_or_commit(node_env: NodeEnv) -> None:
  block = signed_candidate(node_env, 1)
  prepare = vote(node_env, PREPARE, "node1", block)
  forged = replace(block, proposer_signature=prepare.signature)
  context_key = node_env.validator_keys["node1"].public_key
  assert not verify_canonical(context_key, block.preimage_dict(), prepare.signature)
  assert forged.proposer_signature != block.proposer_signature
  forged_commit = CommitSignature("node1", prepare.signature)
  assert not verify_canonical(
    context_key,
    {"domain": "blockchain_core/pbft-commit/v1", "block_hash": block.block_hash},
    forged_commit.signature,
  )


def test_commit_message_signature_is_a_valid_core_commit_signature(node_env: NodeEnv, boot) -> None:
  context: NodeContext = boot(node_env.env)
  block = signed_candidate(node_env, 1)
  commits = tuple(
    CommitSignature(node_id, vote(node_env, COMMIT, node_id, block).signature)
    for node_id in ("node1", "node2", "node3")
  )
  finalized = replace(block, commit_signatures=commits)
  genesis = context.current_blocks()[0]
  assert context.validator.extension(genesis, [finalized]).valid  # attached as received
  tampered = replace(
    block,
    commit_signatures=(
      *commits[:2],
      CommitSignature("node3", vote(node_env, PREPARE, "node3", block).signature),
    ),
  )
  result = context.validator.extension(genesis, [tampered])
  assert not result.valid and result.failure_type == "quorum"
  # the message signature verifies exactly like sign_commit's payload
  reference = sign_commit(block, "node2", node_env.validator_keys["node2"].private_key)
  message = vote(node_env, COMMIT, "node2", block)
  public = node_env.validator_keys["node2"].public_key
  payload = {"domain": "blockchain_core/pbft-commit/v1", "block_hash": block.block_hash}
  assert verify_canonical(public, payload, reference.signature)
  assert verify_canonical(public, payload, message.signature)


# ----------------------------------------------------------------- PbftReceiver


class _Engine:
  def __init__(self) -> None:
    self.submitted: list[PbftMessage] = []

  def submit(self, message: PbftMessage) -> None:
    self.submitted.append(message)


def _receiver(valid: set[str]) -> tuple[PbftReceiver, _Engine, list[tuple[str, str]]]:
  engine, flags = _Engine(), []
  receiver = PbftReceiver(
    engine,  # type: ignore[arg-type]
    is_validator=lambda node_id: node_id in valid,
    flag=lambda peer, reason: flags.append((peer, reason)),
  )
  return receiver, engine, flags


def test_receiver_forwards_a_matching_message() -> None:
  receiver, engine, flags = _receiver({"node2"})
  run(receiver.on_message("node2", _wire(PREPARE)))
  assert len(engine.submitted) == 1 and flags == []


def test_receiver_drops_node_id_that_differs_from_link_id() -> None:
  receiver, engine, flags = _receiver({"node2", "node3"})
  run(receiver.on_message("node3", _wire(PREPARE, node_id="node2")))
  assert engine.submitted == [] and [p for p, _ in flags] == ["node3"]


def test_receiver_drops_non_validator_link() -> None:
  receiver, engine, flags = _receiver({"node2"})
  run(receiver.on_message("peer-x", _wire(PREPARE, node_id="peer-x")))
  assert engine.submitted == [] and [p for p, _ in flags] == ["peer-x"]


def test_receiver_drops_and_flags_malformed() -> None:
  receiver, engine, flags = _receiver({"node2"})
  run(receiver.on_message("node2", _wire(PREPARE, view=True)))
  run(receiver.on_message("node2", _wire(PREPARE, extra=1)))
  assert engine.submitted == [] and len(flags) == 2


def test_is_pbft_message() -> None:
  assert is_pbft_message({"type": "pbft_prepare"}) and is_pbft_message({"type": "pbft_x"})
  assert not is_pbft_message({"type": "block"}) and not is_pbft_message({"type": 5})
  assert not is_pbft_message({})


def test_pow_node_ignores_pbft_without_flag_or_state_change(node_env: NodeEnv) -> None:
  async def scenario() -> None:
    async with Cluster(node_env, ids=("node1",), mode="pow") as c:
      node = c["node1"]
      assert node.app.state.pbft_receiver is not None
      before = node.context.current_blocks()
      block = signed_candidate(node_env, 1)
      for kind in (PRE_PREPARE, PREPARE, COMMIT):
        await node.app.state.pbft_receiver.on_message(
          "node2", vote(node_env, kind, "node2", block).to_wire()
        )
      await node.app.state.pbft_receiver.on_message("node2", {"type": "pbft_garbage"})
      assert node.manager.flags == {}
      assert node.context.current_blocks() == before and node.tip == 0
      assert len(node.context.mempool) == 0

  run(scenario())


def test_non_validator_link_cannot_inject_votes_into_a_running_node(node_env: NodeEnv) -> None:
  block = signed_candidate(node_env, 1)

  async def scenario() -> None:
    async with Cluster(node_env, ids=("node2",), mode="pbft") as c:
      node = c["node2"]
      receiver = node.app.state.pbft_receiver
      await receiver.on_message("stranger", vote(node_env, PRE_PREPARE, "node1", block).to_wire())
      await receiver.on_message("node3", vote(node_env, PREPARE, "node4", block).to_wire())
      await drain(node)
      assert node.engine.round(1) is None
      assert node.manager.flags.get("stranger", 0) == 1 and node.manager.flags.get("node3", 0) == 1

  run(scenario())


# ------------------------------------------------------ pre-prepare receipt rules


def test_pre_prepare_from_non_primary_is_flagged_and_ignored(node_env: NodeEnv) -> None:
  block = signed_candidate(node_env, 1, proposer="node3")

  async def scenario() -> None:
    async with Cluster(node_env, ids=("node2",), mode="pbft") as c:
      node = c["node2"]
      sent = record_sends(node)
      feed(node, vote(node_env, PRE_PREPARE, "node3", block))
      await drain(node)
      assert node.engine.round(1) is None
      assert sent_of(sent, "pbft_prepare") == []
      assert node.manager.flags.get("node3", 0) >= 1

  run(scenario())


def test_second_pre_prepare_does_not_replace_locked_candidate(node_env: NodeEnv) -> None:
  first = signed_candidate(node_env, 1)
  second = signed_candidate(node_env, 2)
  assert first.block_hash != second.block_hash

  async def scenario() -> None:
    async with Cluster(node_env, ids=("node2",), mode="pbft") as c:
      node = c["node2"]
      sent = record_sends(node)
      feed(node, vote(node_env, PRE_PREPARE, "node1", first))
      await until_candidate(node)
      feed(node, vote(node_env, PRE_PREPARE, "node1", second))
      await drain(node)
      current = node.engine.round(1)
      assert current.candidate.block_hash == first.block_hash
      assert ("pbft_pre_prepare", "node1", first.block_hash, second.block_hash) in current.conflicts
      assert {m["block_hash"] for m in sent_of(sent, "pbft_prepare")} == {first.block_hash}
      assert node.engine.prepare_votes(current) == 2

  run(scenario())


def test_conflicting_second_prepare_is_not_counted(node_env: NodeEnv) -> None:
  block = signed_candidate(node_env, 1)

  async def scenario() -> None:
    async with Cluster(node_env, ids=("node2",), mode="pbft") as c:
      node = c["node2"]
      # node3 first votes for another hash, then for ours: the first vote stays
      feed(node, vote(node_env, PREPARE, "node3", block, block_hash=HASH))
      feed(node, vote(node_env, PRE_PREPARE, "node1", block))
      await until_candidate(node)
      feed(node, vote(node_env, PREPARE, "node3", block))
      await drain(node)
      current = node.engine.round(1)
      assert current.prepares["node3"] == HASH
      assert ("pbft_prepare", "node3", HASH, block.block_hash) in current.conflicts
      assert node.engine.prepare_votes(current) == 2 and not current.prepared
      # and the reverse order: our hash first, then a different one
      feed(node, vote(node_env, PREPARE, "node4", block))
      await drain(node)
      assert node.engine.prepare_votes(current) == 3 and current.prepared
      feed(node, vote(node_env, PREPARE, "node4", block, block_hash=HASH))
      await drain(node)
      assert current.prepares["node4"] == block.block_hash

  run(scenario())


def test_forged_prepare_signature_is_not_counted(node_env: NodeEnv) -> None:
  block = signed_candidate(node_env, 1)

  async def scenario() -> None:
    async with Cluster(node_env, ids=("node2",), mode="pbft") as c:
      node = c["node2"]
      feed(node, vote(node_env, PRE_PREPARE, "node1", block))
      await until_candidate(node)
      good = vote(node_env, PREPARE, "node3", block)
      feed(node, replace(good, node_id="node4"))  # node3's signature claimed by node4
      feed(node, replace(good, signature=vote(node_env, COMMIT, "node3", block).signature))
      await drain(node)
      current = node.engine.round(1)
      assert "node4" not in current.prepares and "node3" not in current.prepares
      assert node.engine.prepare_votes(current) == 2
      assert node.manager.flags.get("node4", 0) >= 1 and node.manager.flags.get("node3", 0) >= 1

  run(scenario())


def test_forged_commit_signature_is_not_counted(node_env: NodeEnv) -> None:
  block = signed_candidate(node_env, 1)

  async def scenario() -> None:
    async with Cluster(node_env, ids=("node2",), mode="pbft") as c:
      node = c["node2"]
      feed(
        node, vote(node_env, PRE_PREPARE, "node1", block), vote(node_env, PREPARE, "node3", block)
      )
      await until_prepared(node)
      current = node.engine.round(1)
      bad = vote(node_env, PREPARE, "node4", block).signature  # a prepare signature as a commit
      feed(
        node,
        replace(vote(node_env, COMMIT, "node4", block), signature=bad),
        replace(vote(node_env, COMMIT, "node1", block), node_id="node4"),
      )
      await drain(node)
      assert node.tip == 0 and set(node.engine.commit_votes(current)) == {"node2"}
      feed(node, vote(node_env, COMMIT, "node3", block), vote(node_env, COMMIT, "node1", block))
      await until_tip(node, 1)

  run(scenario())


async def until_candidate(node) -> None:
  await until(lambda: node.engine.round(1) is not None and node.engine.round(1).candidate)


async def until_prepared(node) -> None:
  await until(lambda: node.engine.round(1) is not None and node.engine.round(1).prepared)


async def until_tip(node, tip: int) -> None:
  await until(lambda: node.tip == tip)


# ------------------------------------------------------------- candidate screening


def _bad_merkle(env: NodeEnv) -> Block:
  block = signed_candidate(env, 1)
  return resign(env, rehash(block, merkle_root="0" * 64))


def _bad_record_signature(env: NodeEnv) -> Block:
  block = signed_candidate(env, 1)
  tampered = replace(block.document_records[0], signature=_record(env, 9).signature)
  return resign(
    env, rehash(block, document_records=(tampered,), merkle_root=build_root([tampered]))
  )


def _with_commits(env: NodeEnv) -> Block:
  block = signed_candidate(env, 1)
  return replace(
    block, commit_signatures=(sign_commit(block, "node1", env.validator_keys["node1"]),)
  )


def _back_dated(env: NodeEnv) -> Block:
  return signed_candidate(env, 1, timestamp=now_ms() - 10 * 60_000)


def _future(env: NodeEnv) -> Block:
  return signed_candidate(env, 1, timestamp=now_ms() + 10 * 60_000)


def _below_tip(env: NodeEnv) -> Block:
  return signed_candidate(env, 1, timestamp=build_genesis_block().timestamp - 1)


def _wrong_view(env: NodeEnv) -> Block:
  return signed_candidate(env, 1, view=3)


def _wrong_proposer(env: NodeEnv) -> Block:
  return signed_candidate(env, 1, proposer="node2")


def _unsigned(env: NodeEnv) -> Block:
  return replace(signed_candidate(env, 1), proposer_signature=None)


def _forged_proposer_signature(env: NodeEnv) -> Block:
  block = signed_candidate(env, 1)
  other = signed_candidate(env, 2)
  return replace(block, proposer_signature=other.proposer_signature)


def _wrong_index(env: NodeEnv) -> Block:
  block = signed_candidate(env, 1)
  return resign(env, rehash(block, index=2))


def _wrong_parent(env: NodeEnv) -> Block:
  block = signed_candidate(env, 1)
  return resign(env, rehash(block, previous_hash="11" * 32))


def _stale_hash(env: NodeEnv) -> Block:
  return replace(signed_candidate(env, 1), block_hash="22" * 32)


def _pow_algorithm(env: NodeEnv) -> Block:
  block = signed_candidate(env, 1)
  return resign(env, rehash(block, algorithm="pow", sealed_consensus={"nonce": 0, "difficulty": 1}))


_INVALID = [
  (_bad_merkle, "merkle"),
  (_bad_record_signature, None),
  (_with_commits, "structural"),
  (_back_dated, "timestamp_too_old"),
  (_future, "timestamp_in_future"),
  (_below_tip, None),
  (_wrong_view, "structural"),
  (_wrong_proposer, "not_primary"),
  (_unsigned, "unsigned"),
  (_forged_proposer_signature, None),
  (_wrong_index, None),
  (_wrong_parent, None),
  (_stale_hash, None),
  (_pow_algorithm, "not_primary"),
]
_TRANSIENT = {"_back_dated", "_future", "_below_tip"}
_IDS = [build.__name__.lstrip("_") for build, _ in _INVALID]


@pytest.mark.parametrize(("build", "reason"), _INVALID, ids=_IDS)
def test_screen_candidate_rejects(build, reason, node_env: NodeEnv, boot) -> None:
  context: NodeContext = boot(node_env.env)
  block = build(node_env)
  verdict = context.gateway.screen_candidate(
    block, primary_id="node1", view=0, known=context.chain_state.has_document
  )
  assert not verdict.accepted and verdict.kind == "reject"
  if reason is not None:
    assert verdict.reason == reason


def test_screen_candidate_accepts_a_good_candidate(node_env: NodeEnv, boot) -> None:
  context: NodeContext = boot(node_env.env)
  block = signed_candidate(node_env, 1)
  verdict = context.gateway.screen_candidate(
    block, primary_id="node1", view=0, known=context.chain_state.has_document
  )
  assert verdict.accepted
  # the lower timestamp bound lies just inside the skew window
  edge = signed_candidate(node_env, 1, timestamp=now_ms() - 30_000)
  assert context.gateway.screen_candidate(
    edge, primary_id="node1", view=0, known=context.chain_state.has_document
  ).accepted


def test_screen_candidate_rejects_already_known_document(node_env: NodeEnv, boot) -> None:
  context: NodeContext = boot(node_env.env)
  block = signed_candidate(node_env, 1)
  verdict = context.gateway.screen_candidate(
    block, primary_id="node1", view=0, known=lambda _hash: True
  )
  assert verdict.reason == "duplicate_document"


def test_screen_candidate_rejects_a_stale_parent_after_the_tip_moves(
  node_env: NodeEnv, boot
) -> None:
  context: NodeContext = boot(node_env.env)
  assert run(context.chain_state.append(_finalized(node_env, 1)))
  stale = signed_candidate(node_env, 2)  # still built on genesis
  verdict = context.gateway.screen_candidate(
    stale, primary_id="node1", view=0, known=context.chain_state.has_document
  )
  assert verdict.reason == "link"


def _finalized(env: NodeEnv, seed: int) -> Block:
  return pbft_block(env, build_genesis_block(), seed)


@pytest.mark.parametrize(("build", "_reason"), _INVALID, ids=_IDS)
def test_invalid_candidate_gets_no_prepare(build, _reason, node_env: NodeEnv) -> None:  # UC-6-E1
  async def scenario() -> None:
    async with Cluster(node_env, ids=("node2",), mode="pbft") as c:
      node = c["node2"]
      sent = record_sends(node)
      block = build(node_env)
      feed(node, vote(node_env, PRE_PREPARE, "node1", block, block_hash=block.block_hash))
      await drain(node)
      current = node.engine.round(1)
      assert current is None or current.candidate is None
      assert sent_of(sent, "pbft_prepare") == [] and sent_of(sent, "pbft_commit") == []
      assert node.tip == 0
      name = build.__name__
      if name in _TRANSIENT:  # clock-dependent: no flag, not locked out
        assert node.manager.flags.get("node1", 0) == 0
      elif name != "_wrong_index":  # (a wrong index is a look-ahead message, not this round)
        assert node.manager.flags.get("node1", 0) >= 1
      good = signed_candidate(node_env, 5)
      feed(node, vote(node_env, PRE_PREPARE, "node1", good))
      await drain(node)
      follow = node.engine.round(1)
      accepted = follow is not None and follow.candidate is not None
      if name in _TRANSIENT or name == "_wrong_index":
        assert accepted
        assert {m["block_hash"] for m in sent_of(sent, "pbft_prepare")} == {good.block_hash}
      else:  # one candidate per slot: after a rejected one nothing else is screened
        assert not accepted and sent_of(sent, "pbft_prepare") == []

  run(scenario())


def test_pre_prepare_with_mismatched_envelope_gets_no_prepare(node_env: NodeEnv) -> None:
  block = signed_candidate(node_env, 1)

  async def scenario() -> None:
    async with Cluster(node_env, ids=("node2",), mode="pbft") as c:
      node = c["node2"]
      sent = record_sends(node)
      # signed envelope claims another hash than the carried block has
      feed(node, vote(node_env, PRE_PREPARE, "node1", block, block_hash=HASH))
      await drain(node)
      current = node.engine.round(1)
      assert current is None or current.candidate is None
      assert sent_of(sent, "pbft_prepare") == []
      assert node.manager.flags.get("node1", 0) >= 1

  run(scenario())
