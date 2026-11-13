"""Slice 17: the PBFT three-phase protocol on a cluster (UC-6; QA TC-6.x, CN-TC-17.3).

Full rounds run on `Cluster(mode="pbft")`; the phase-ordering / duplicate / reorder cases drive
ONE replica (node2) directly through `engine.submit` with votes signed by the other members.
"""

from __future__ import annotations

import asyncio

import pytest
from chain_factory import pbft_chain
from network_helpers import Cluster, until
from node_helpers import NodeEnv, pem_of
from pbft_helpers import (
  IDS,
  drain,
  feed,
  propose,
  record_sends,
  sent_of,
  signed_candidate,
  vote,
)
from sync_helpers import run

from blockchain_core import generate_node_keypair
from node.consensus.pbft.messages import COMMIT, PRE_PREPARE, PREPARE

_LONE = ("node2",)


def _cluster(node_env: NodeEnv, ids: tuple[str, ...] = IDS) -> Cluster:
  return Cluster(node_env, ids=ids, mode="pbft")


async def _finalize_one(c: Cluster, env: NodeEnv, seed: int = 1) -> None:
  await c.all_connected()
  await propose(c["node1"], env, seed)
  await until(lambda: all(n.tip == 1 for n in c.nodes.values()))


# ------------------------------------------------------------------------ TC-6.1


def test_full_round_finalizes_same_block_everywhere(node_env: NodeEnv) -> None:  # TC-6.1
  async def scenario() -> None:
    async with _cluster(node_env) as c:
      await _finalize_one(c, node_env)
      blocks = {n.context.current_blocks()[1].block_hash for n in c.nodes.values()}
      assert len(blocks) == 1
      for node in c.nodes.values():
        chain = node.context.current_blocks()
        block = chain[1]
        assert block.algorithm == "pbft" and block.proposer_id == "node1"
        assert dict(block.sealed_consensus) == {"view_number": 0}
        signers = [s.node_id for s in block.commit_signatures]
        assert len(signers) == len(set(signers)) >= node.engine.quorum == 3
        assert set(signers) <= set(IDS)
        assert node.context.validator.full(chain).valid  # the core quorum check
        snapshot = node.context.validity_cache.snapshot
        assert snapshot.chain_valid and snapshot.quorum_status == "healthy"
        assert snapshot.tip_index == 1
        assert list(c.stored_blocks(node.node_id)) == list(chain)  # persisted == memory
        assert len(node.context.mempool) == 0
        assert node.engine.round(1) is None  # the round is closed

  run(scenario())


def test_two_consecutive_rounds(node_env: NodeEnv) -> None:
  async def scenario() -> None:
    async with _cluster(node_env) as c:
      await _finalize_one(c, node_env, 1)
      await propose(c["node1"], node_env, 2)
      await until(lambda: all(n.tip == 2 for n in c.nodes.values()))
      for node in c.nodes.values():
        assert node.context.validator.full(node.context.current_blocks()).valid
      assert len({n.context.current_blocks()[2].block_hash for n in c.nodes.values()}) == 1

  run(scenario())


# ------------------------------------------------------------------------ TC-6.2


def test_peerinfo_peers_never_change_quorum_or_receive_votes(node_env: NodeEnv) -> None:  # TC-6.2
  extra_pems = [pem_of(generate_node_keypair()) for _ in range(300)]
  extra_ids = {f"extra-{i:03d}" for i in range(300)}

  async def scenario() -> None:
    async with _cluster(node_env) as c:
      await c.all_connected()
      spies = {nid: record_sends(node) for nid, node in c.nodes.items()}
      for node in c.nodes.values():
        for i, pem in enumerate(extra_pems):
          assert node.context.peers.register(f"extra-{i:03d}", "nowhere", 7000 + i, pem)
        assert node.engine.quorum == 3  # unchanged by 300 PeerInfo peers
        assert len(node.engine.members()) == 4
      await propose(c["node1"], node_env, 1)
      await until(lambda: all(n.tip == 1 for n in c.nodes.values()), timeout=15.0)
      assert len({n.context.current_blocks()[1].block_hash for n in c.nodes.values()}) == 1
      for node in c.nodes.values():
        assert node.context.validator.full(node.context.current_blocks()).valid
      votes = 0
      for sent in spies.values():
        for message, only in sent:
          if str(message.get("type", "")).startswith("pbft_"):
            votes += 1
            assert only is not None, "a PBFT message went out unfiltered"
            assert only <= set(IDS) and not (only & extra_ids)
      assert votes >= 4 * 2

  run(scenario())


# ------------------------------------------------------------------------ TC-6.3


def test_primary_never_sends_prepare_but_reaches_quorum(node_env: NodeEnv) -> None:  # TC-6.3
  async def scenario() -> None:
    async with _cluster(node_env) as c:
      await c.all_connected()
      spies = {nid: record_sends(node) for nid, node in c.nodes.items()}
      await propose(c["node1"], node_env, 1)
      await until(lambda: all(n.tip == 1 for n in c.nodes.values()))
      assert sent_of(spies["node1"], "pbft_pre_prepare")
      assert sent_of(spies["node1"], "pbft_commit")
      assert sent_of(spies["node1"], "pbft_prepare") == []  # pre-prepare is its prepare vote
      for replica in ("node2", "node3", "node4"):
        assert len({m["block_hash"] for m in sent_of(spies[replica], "pbft_prepare")}) == 1
        assert sent_of(spies[replica], "pbft_pre_prepare") == []

  run(scenario())


def test_prepare_votes_count_primary_implicitly_and_ignore_its_prepare(
  node_env: NodeEnv,
) -> None:  # TC-6.3
  block = signed_candidate(node_env, 1)

  async def scenario() -> None:
    async with _cluster(node_env, _LONE) as c:
      node = c["node2"]
      sent = record_sends(node)
      feed(node, vote(node_env, PRE_PREPARE, "node1", block))
      await until(lambda: node.engine.round(1) and node.engine.round(1).candidate)
      current = node.engine.round(1)
      assert node.engine.prepare_votes(current) == 2  # implicit primary + our own prepare
      assert len(sent_of(sent, "pbft_prepare")) >= 1
      feed(node, vote(node_env, PREPARE, "node1", block))  # a prepare "from" the primary
      await drain(node)
      assert "node1" not in current.prepares
      assert node.engine.prepare_votes(current) == 2 and not current.prepared
      assert node.manager.flags.get("node1", 0) >= 1
      feed(node, vote(node_env, PREPARE, "node3", block))
      await until(lambda: current.prepared)
      assert node.engine.prepare_votes(current) == 3
      assert len(sent_of(sent, "pbft_commit")) >= 1

  run(scenario())


# ------------------------------------------------------------------------ TC-6.4


def test_replicas_never_propose(node_env: NodeEnv) -> None:  # TC-6.4
  async def scenario() -> None:
    async with _cluster(node_env) as c:
      await c.all_connected()
      spies = {nid: record_sends(node) for nid, node in c.nodes.items()}
      for position, replica in enumerate(("node2", "node3", "node4"), start=10):
        await propose(c[replica], node_env, position)  # records only in replica mempools
      await asyncio.sleep(0.3)
      assert all(n.tip == 0 for n in c.nodes.values())
      await propose(c["node1"], node_env, 1)
      await until(lambda: all(n.tip == 1 for n in c.nodes.values()))
      await asyncio.sleep(0.1)
      for replica in ("node2", "node3", "node4"):
        assert sent_of(spies[replica], "pbft_pre_prepare") == []
        assert all(n.tip == 1 for n in c.nodes.values())  # replica records were never proposed
      assert not c["node2"].engine.is_primary and c["node1"].engine.is_primary

  run(scenario())


# ------------------------------------------------------------------------ TC-6.5


def test_one_member_down_still_finalizes(node_env: NodeEnv) -> None:  # TC-6.5
  async def scenario() -> None:
    async with _cluster(node_env) as c:
      await c.all_connected()
      await c.network.sever(c["node4"].address)
      await propose(c["node1"], node_env, 1)
      live = [c["node1"], c["node2"], c["node3"]]
      await until(lambda: all(n.tip == 1 for n in live))
      assert c["node4"].tip == 0
      for node in live:
        chain = node.context.current_blocks()
        signers = {s.node_id for s in chain[1].commit_signatures}
        assert signers == {"node1", "node2", "node3"}  # exactly the 3 commits that exist
        snapshot = node.context.validity_cache.snapshot
        assert snapshot.chain_valid and snapshot.quorum_status == "healthy"  # not a fault state
        assert node.context.validator.full(chain).valid

  run(scenario())


# ------------------------------------------------------------------ TC-6.9 / UC-6-E3


def test_commits_alone_never_finalize(node_env: NodeEnv) -> None:  # TC-6.9
  block = signed_candidate(node_env, 1)

  async def scenario() -> None:
    async with _cluster(node_env, _LONE) as c:
      node = c["node2"]
      sent = record_sends(node)
      commits = [vote(node_env, COMMIT, n, block) for n in ("node1", "node3", "node4")]
      feed(node, *commits)  # all three other members commit before any pre-prepare
      await until(lambda: node.engine.round(1) and len(node.engine.round(1).commits) == 3)
      current = node.engine.round(1)
      assert node.tip == 0 and current.candidate is None and not current.prepared
      assert node.engine.commit_votes(current) == {}
      feed(node, vote(node_env, PRE_PREPARE, "node1", block))  # accepted, but prepared needs 3
      await until(lambda: current.candidate is not None)
      await drain(node)
      assert node.tip == 0 and not current.prepared
      assert node.engine.commit_votes(current) == {}  # held, not counted
      assert sent_of(sent, "pbft_commit") == []  # we have not committed either
      feed(node, vote(node_env, PREPARE, "node3", block))  # now this node is prepared
      await until(lambda: node.tip == 1)
      chain = node.context.current_blocks()
      assert chain[1].block_hash == block.block_hash
      assert {s.node_id for s in chain[1].commit_signatures} >= {"node1", "node2", "node3"}
      assert node.context.validator.full(chain).valid

  run(scenario())


def test_prepared_replica_with_too_few_commits_waits(node_env: NodeEnv) -> None:  # TC-6.9
  block = signed_candidate(node_env, 1)

  async def scenario() -> None:
    async with _cluster(node_env, _LONE) as c:
      node = c["node2"]
      feed(
        node, vote(node_env, PRE_PREPARE, "node1", block), vote(node_env, PREPARE, "node3", block)
      )
      await until(lambda: node.engine.round(1) and node.engine.round(1).prepared)
      current = node.engine.round(1)
      feed(node, vote(node_env, COMMIT, "node3", block))  # own + node3 = 2 < 3
      await drain(node)
      assert node.tip == 0 and set(node.engine.commit_votes(current)) == {"node2", "node3"}
      feed(node, vote(node_env, COMMIT, "node4", block))
      await until(lambda: node.tip == 1)

  run(scenario())


def test_commit_with_mismatched_seq_is_not_counted(node_env: NodeEnv) -> None:  # TC-6.9
  block = signed_candidate(node_env, 1)

  async def scenario() -> None:
    async with _cluster(node_env, _LONE) as c:
      node = c["node2"]
      feed(
        node, vote(node_env, PRE_PREPARE, "node1", block), vote(node_env, PREPARE, "node3", block)
      )
      await until(lambda: node.engine.round(1) and node.engine.round(1).prepared)
      current = node.engine.round(1)
      feed(
        node,
        vote(node_env, COMMIT, "node3", block),
        vote(node_env, COMMIT, "node4", block, seq=2),  # right hash, wrong seq
        vote(node_env, COMMIT, "node1", block, seq=7),  # far ahead: a sync hint, never a vote
      )
      await drain(node)
      assert "node4" not in current.commits and "node1" not in current.commits
      assert node.tip == 0 and set(node.engine.commit_votes(current)) == {"node2", "node3"}
      feed(node, vote(node_env, COMMIT, "node4", block))  # the same vote with the right seq
      await until(lambda: node.tip == 1)

  run(scenario())


def test_commit_for_another_hash_is_not_counted(node_env: NodeEnv) -> None:  # TC-6.9
  block = signed_candidate(node_env, 1)
  other = signed_candidate(node_env, 2)

  async def scenario() -> None:
    async with _cluster(node_env, _LONE) as c:
      node = c["node2"]
      feed(
        node, vote(node_env, PRE_PREPARE, "node1", block), vote(node_env, PREPARE, "node3", block)
      )
      await until(lambda: node.engine.round(1) and node.engine.round(1).prepared)
      current = node.engine.round(1)
      feed(node, vote(node_env, COMMIT, "node3", block), vote(node_env, COMMIT, "node4", other))
      await drain(node)
      assert node.tip == 0 and set(node.engine.commit_votes(current)) == {"node2", "node3"}

  run(scenario())


# ------------------------------------------------------------------ TC-6.14 / UC-6-EC3


def test_duplicated_and_reordered_messages_count_once(node_env: NodeEnv) -> None:  # TC-6.14
  block = signed_candidate(node_env, 1)
  pre = vote(node_env, PRE_PREPARE, "node1", block)
  prepares = [vote(node_env, PREPARE, n, block) for n in ("node3", "node4")]
  commits = [vote(node_env, COMMIT, n, block) for n in ("node1", "node3", "node4")]

  async def scenario() -> None:
    async with _cluster(node_env, _LONE) as c:
      node = c["node2"]
      sent = record_sends(node)
      for _ in range(4):  # votes first, repeated, interleaved in odd order
        feed(node, *reversed(commits), *reversed(prepares))
      await until(lambda: node.engine.round(1) and len(node.engine.round(1).commits) == 3)
      current = node.engine.round(1)
      assert node.tip == 0 and len(current.prepares) == 2 and current.candidate is None
      for _ in range(3):
        feed(node, pre, *prepares, *commits)
      await until(lambda: node.tip == 1)
      for _ in range(3):  # late duplicates after finalization
        feed(node, pre, *prepares, *commits)
      await drain(node)
      chain = node.context.current_blocks()
      assert len(chain) == 2 and node.tip == 1
      assert node.engine.finalized_rounds == 1
      assert len(c.stored_blocks("node2")) == 2
      signers = [s.node_id for s in chain[1].commit_signatures]
      assert len(signers) == len(set(signers))
      assert node.context.validator.full(chain).valid
      assert len({m["block_hash"] for m in sent_of(sent, "pbft_prepare")}) == 1
      assert len({m["block_hash"] for m in sent_of(sent, "pbft_commit")}) == 1

  run(scenario())


def test_duplicated_votes_do_not_reach_quorum_alone(node_env: NodeEnv) -> None:  # TC-6.14
  block = signed_candidate(node_env, 1)

  async def scenario() -> None:
    async with _cluster(node_env, _LONE) as c:
      node = c["node2"]
      feed(node, vote(node_env, PRE_PREPARE, "node1", block))
      for _ in range(10):  # one member repeating a prepare is still one vote
        feed(node, vote(node_env, PREPARE, "node3", block))
      await until(lambda: node.engine.round(1) and node.engine.round(1).candidate)
      await drain(node)
      current = node.engine.round(1)
      assert node.engine.prepare_votes(current) == 3  # primary + self + node3
      assert current.prepared  # quorum 3 reached with exactly three distinct members

  run(scenario())


# --------------------------------------------------------------------- CN-TC-17.3


@pytest.mark.parametrize("target", ["node1", "node2"])
def test_replace_during_open_round_abandons_it(
  node_env: NodeEnv, target: str
) -> None:  # CN-TC-17.3
  async def scenario() -> None:
    async with _cluster(node_env, ("node1", "node2")) as c:  # no quorum: the round stays open
      await c.all_connected()
      spy = record_sends(c["node1"])
      await propose(c["node1"], node_env, 1)
      await until(
        lambda: all(n.engine.round(1) and n.engine.round(1).candidate for n in c.nodes.values())
      )
      first = c["node1"].engine.round(1).candidate.block_hash
      assert c[target].tip == 0
      # a second pending record: after the replace the primary proposes on the NEW tip
      await propose(c["node1"], node_env, 50)
      longer = pbft_chain(node_env, 2)
      assert longer[1].block_hash != first
      node = c[target]
      assert await node.context.chain_state.replace(longer, node.context.validator.full)
      await until(lambda: node.engine.round(1) is None)
      assert node.tip == 2
      if target == "node1":
        await until(lambda: sent_of(spy, "pbft_pre_prepare", 3))  # restarted on the new tip
        restarted = sent_of(spy, "pbft_pre_prepare", 3)[0]
        assert restarted["block"]["previous_hash"] == longer[2].block_hash
        assert restarted["block"]["index"] == 3
      # never a second, different pre-prepare for (view 0, seq 1)
      assert {m["block_hash"] for m in sent_of(spy, "pbft_pre_prepare", 1)} == {first}

  run(scenario())


def test_primary_resends_the_same_pre_prepare(node_env: NodeEnv) -> None:  # TC-6.14 / safety
  async def scenario() -> None:
    async with _cluster(node_env, ("node1", "node2")) as c:
      await c.all_connected()
      spy = record_sends(c["node1"])
      await propose(c["node1"], node_env, 1)
      await until(lambda: len(sent_of(spy, "pbft_pre_prepare", 1)) >= 2, timeout=5.0)  # resend tick
      assert len({m["block_hash"] for m in sent_of(spy, "pbft_pre_prepare", 1)}) == 1
      await propose(c["node1"], node_env, 2)  # more records never create a second candidate
      await asyncio.sleep(0.1)
      assert len({m["block_hash"] for m in sent_of(spy, "pbft_pre_prepare", 1)}) == 1

  run(scenario())
