"""Slice 16b: fork resolution - adoption rules, the PoW tie-break, PBFT safety, mining restart."""

from __future__ import annotations

import asyncio
import dataclasses
import logging
from collections.abc import Sequence

import httpx
import pytest
from chain_factory import _record, pbft_block, pbft_chain, pow_chain
from network_helpers import Cluster, until
from node_helpers import NodeEnv
from sync_helpers import (
  blocks_of,
  extend,
  force_install,
  install,
  lowest_tip,
  peer_of,
  run,
  slow_sync_env,
  sync_of,
)

from blockchain_core import Block, build_genesis_block, pow_target
from node.sync import finalized_height, pbft_prefers, pow_prefers
from node.validity_cache import QUORUM_BYZANTINE, QUORUM_HEALTHY

GENESIS = build_genesis_block()


def _with_hash(block: Block, block_hash: str) -> Block:
  return dataclasses.replace(block, block_hash=block_hash)


def _chain_of(length: int, tip_hash: str) -> list[Block]:
  """`length` blocks; only the tip hash matters to the adoption rules."""
  blocks = [GENESIS] * (length - 1)
  return [*blocks, _with_hash(GENESIS, tip_hash)]


def _pbft_extend(env: NodeEnv, blocks: Sequence[Block], seeds: Sequence[int]) -> list[Block]:
  chain = list(blocks)
  for seed in seeds:
    chain.append(pbft_block(env, chain[-1], seed))
  return chain


# -------------------------------------------------------------- adoption rules (units)

LOW = "1" + "0" * 63
MID = "7" + "0" * 63
HIGH = "f" * 64  # would sort as negative if read as a signed integer


def test_pow_prefers_the_longer_chain() -> None:  # CN-TC-3.1 / 3.11
  assert pow_prefers(_chain_of(3, HIGH), _chain_of(4, HIGH)) is True
  assert pow_prefers(_chain_of(4, LOW), _chain_of(3, LOW)) is False


@pytest.mark.parametrize(
  ("current", "candidate", "expected"),
  [(HIGH, LOW, True), (LOW, HIGH, False), (MID, LOW, True), (LOW, MID, False), (LOW, LOW, False)],
)
def test_pow_equal_length_prefers_the_lowest_tip_hash(
  current: str, candidate: str, expected: bool
) -> None:  # CN-TC-3.11: unsigned integer comparison, never arrival order
  assert pow_prefers(_chain_of(3, current), _chain_of(3, candidate)) is expected


def test_pbft_prefers_the_higher_finalized_height() -> None:  # CN-TC-3.5
  low, high = pbft_chain_stub(3), pbft_chain_stub(5)
  assert finalized_height(high) == 4 and finalized_height(low) == 2
  assert pbft_prefers(low, high) is True
  assert pbft_prefers(high, low) is False
  assert pbft_prefers(low, low) is False  # equal height is never "better" (no tie-break)


def pbft_chain_stub(length: int) -> list[Block]:
  return [dataclasses.replace(GENESIS, index=i, block_hash=f"{i:064x}") for i in range(length)]


# ----------------------------------------------------------------- PoW, equal length


@pytest.mark.parametrize("prefix_len", [1, 3], ids=["fork-at-1", "fork-at-3"])
def test_equal_length_pow_forks_resolve_to_the_lowest_tip_in_either_order(
  node_env: NodeEnv, prefix_len: int
) -> None:
  # CN-TC-3.11: A-then-B and B-then-A on two fresh nodes end on the same chain
  slow_sync_env(node_env)
  prefix = pow_chain(node_env, prefix_len - 1)
  a = extend(node_env, prefix, [101, 102])
  b = extend(node_env, prefix, [201, 202])
  winner = lowest_tip(a, b)
  assert a[-1].block_hash != b[-1].block_hash

  async def go() -> None:
    async with Cluster(
      node_env, ids=("node1", "node2", "node3", "node4"), mine=False, register_peers=False
    ) as cluster:
      n1, n2, n3, n4 = (cluster[f"node{i}"] for i in range(1, 5))
      await install(n1, a)
      await install(n2, b)

      assert await sync_of(n3).sync_with(peer_of(n1)) == "adopted"  # A, then B
      second_a_then_b = await sync_of(n3).sync_with(peer_of(n2))
      assert await sync_of(n4).sync_with(peer_of(n2)) == "adopted"  # B, then A
      second_b_then_a = await sync_of(n4).sync_with(peer_of(n1))

      assert blocks_of(n3) == blocks_of(n4) == tuple(winner)
      assert cluster.stored_blocks("node3") == cluster.stored_blocks("node4") == winner
      # the loser of the tie-break is the one that never replaces anything
      assert sorted([second_a_then_b, second_b_then_a]) == ["adopted", "not_better"]
      assert (second_a_then_b == "adopted") == (winner is b)

  run(go())


def test_equal_length_loser_does_not_download_the_winner_chain(node_env: NodeEnv) -> None:
  # CN-TC-3.11: when our tip hash is the lower one, the probe alone settles it
  slow_sync_env(node_env)
  a = pow_chain(node_env, 4)
  b = extend(node_env, a[:4], [77])
  winner, loser = (a, b) if lowest_tip(a, b) is a else (b, a)

  async def go() -> None:
    async with Cluster(
      node_env, ids=("node1", "node2"), mine=False, register_peers=False
    ) as cluster:
      n1, n2 = cluster["node1"], cluster["node2"]
      await install(n1, winner)
      await install(n2, loser)
      before = len(cluster.chain_fetcher.requests)
      assert await sync_of(n1).sync_with(peer_of(n2)) == "not_better"
      requested = cluster.chain_fetcher.requests[before:]
      assert [from_index for _, from_index, _ in requested] == [4]  # no full download
      assert blocks_of(n1) == tuple(winner)

  run(go())


def test_longer_pow_chain_beats_a_lower_tip_hash(node_env: NodeEnv) -> None:  # CN-TC-3.2 / 3.11
  slow_sync_env(node_env)
  short = pow_chain(node_env, 3)
  long_fork = extend(node_env, short[:2], [61, 62, 63])

  async def go() -> None:
    async with Cluster(
      node_env, ids=("node1", "node2"), mine=False, register_peers=False
    ) as cluster:
      n1, n2 = cluster["node1"], cluster["node2"]
      await install(n1, short)
      await install(n2, long_fork)
      assert await sync_of(n1).sync_with(peer_of(n2)) == "adopted"
      assert blocks_of(n1) == tuple(long_fork)

  run(go())


@pytest.mark.parametrize("relation", ["same", "behind", "behind_fork"])
def test_a_peer_that_is_not_better_changes_nothing(node_env: NodeEnv, relation: str) -> None:
  # CN-TC-3.1 / 3.2: same chain, shorter prefix, or a shorter fork -> not_better, no replace
  slow_sync_env(node_env)
  mine = pow_chain(node_env, 4)
  theirs = {
    "same": mine,
    "behind": mine[:3],
    "behind_fork": extend(node_env, mine[:2], [71]),
  }[relation]

  async def go() -> None:
    async with Cluster(
      node_env, ids=("node1", "node2"), mine=False, register_peers=False
    ) as cluster:
      n1, n2 = cluster["node1"], cluster["node2"]
      await install(n1, mine)
      await install(n2, theirs)
      generation = n1.context.chain_state.generation
      assert await sync_of(n1).sync_with(peer_of(n2)) == "not_better"
      assert blocks_of(n1) == tuple(mine)
      assert n1.context.chain_state.generation == generation  # no replace happened

  run(go())


# --------------------------------------------------------------------------- PBFT


def test_pbft_higher_finalized_height_wins_in_sync(node_env: NodeEnv) -> None:  # CN-TC-3.5
  slow_sync_env(node_env)
  chain = pbft_chain(node_env, 5)

  async def go() -> None:
    async with Cluster(
      node_env, ids=("node1", "node2", "node3"), mode="pbft", mine=False, register_peers=False
    ) as cluster:
      n1, n2, n3 = cluster["node1"], cluster["node2"], cluster["node3"]
      await install(n1, chain[:3])
      await install(n2, chain)
      await install(n3, chain[:3])

      assert await sync_of(n1).sync_with(peer_of(n2)) == "adopted"  # taller finalized height
      assert blocks_of(n1) == tuple(chain)
      assert await sync_of(n2).sync_with(peer_of(n3)) == "not_better"  # shorter: ignored
      assert await sync_of(n2).sync_with(peer_of(n1)) == "not_better"  # identical
      assert blocks_of(n2) == tuple(chain)
      assert n1.context.validity_cache.snapshot.quorum_status == QUORUM_HEALTHY

  run(go())


@pytest.mark.parametrize("peer_extra", [0, 2], ids=["same-height", "peer-taller"])
def test_pbft_differently_finalized_block_at_one_height_is_a_byzantine_event(
  node_env: NodeEnv, caplog: pytest.LogCaptureFixture, peer_extra: int
) -> None:
  # CN-TC-3.12: never tie-broken, never adopted - surfaced as quorum_status + a log event
  slow_sync_env(node_env)
  mine = _pbft_extend(node_env, [GENESIS], [1, 2])
  theirs = _pbft_extend(node_env, [GENESIS], [11, 12, 13, 14][: 2 + peer_extra])
  assert mine[1].block_hash != theirs[1].block_hash

  async def go() -> None:
    async with Cluster(
      node_env, ids=("node1", "node2"), mode="pbft", mine=False, register_peers=False
    ) as cluster:
      n1, n2 = cluster["node1"], cluster["node2"]
      await install(n1, mine)
      await install(n2, theirs)
      assert n1.context.validity_cache.snapshot.quorum_status == QUORUM_HEALTHY

      with caplog.at_level(logging.ERROR):
        assert await sync_of(n1).sync_with(peer_of(n2)) == "byzantine"

      assert blocks_of(n1) == tuple(mine)  # NOT adopted, however tall the peer's chain is
      assert cluster.stored_blocks("node1") == mine
      assert n1.context.validity_cache.snapshot.quorum_status == QUORUM_BYZANTINE
      assert "SAFETY VIOLATION" in caplog.text
      assert n1.manager.flags.get("node2", 0) == 0  # a valid chain is not "misbehaviour"
      transport = httpx.ASGITransport(app=n1.app)
      async with httpx.AsyncClient(transport=transport, base_url="http://node1") as client:
        info = (await client.get("/node/info")).json()
      assert info["quorum_status"] == QUORUM_BYZANTINE and info["chain_valid"] is True

      # symmetric: the other node sees the same violation and also keeps its own chain
      if peer_extra == 0:
        assert await sync_of(n2).sync_with(peer_of(n1)) == "byzantine"
        assert blocks_of(n2) == tuple(theirs)
        assert n2.context.validity_cache.snapshot.quorum_status == QUORUM_BYZANTINE

  run(go())


def test_pbft_byzantine_status_is_sticky_across_later_chain_changes(node_env: NodeEnv) -> None:
  # CN-TC-3.12: a safety violation stays visible until restart
  slow_sync_env(node_env)
  mine = _pbft_extend(node_env, [GENESIS], [1])
  theirs = _pbft_extend(node_env, [GENESIS], [11])

  async def go() -> None:
    async with Cluster(
      node_env, ids=("node1", "node2"), mode="pbft", mine=False, register_peers=False
    ) as cluster:
      n1, n2 = cluster["node1"], cluster["node2"]
      await install(n1, mine)
      await install(n2, theirs)
      assert await sync_of(n1).sync_with(peer_of(n2)) == "byzantine"
      assert await n1.context.chain_state.append(pbft_block(node_env, mine[-1], 2))
      assert n1.context.validity_cache.snapshot.quorum_status == QUORUM_BYZANTINE

  run(go())


def test_pbft_fork_with_an_invalid_chain_is_invalid_not_byzantine(node_env: NodeEnv) -> None:
  # CN-TC-3.12 boundary: a forged "finalized" block without a quorum is a bad peer, not a fork
  slow_sync_env(node_env)
  mine = _pbft_extend(node_env, [GENESIS], [1, 2])
  forged = [GENESIS, dataclasses.replace(pbft_block(node_env, GENESIS, 11), commit_signatures=())]

  async def go() -> None:
    async with Cluster(
      node_env, ids=("node1", "node2"), mode="pbft", mine=False, register_peers=False
    ) as cluster:
      n1, n2 = cluster["node1"], cluster["node2"]
      await install(n1, mine)
      await force_install(n2, [*forged, pbft_block(node_env, forged[1], 12)])
      assert await sync_of(n1).sync_with(peer_of(n2)) == "invalid"
      assert blocks_of(n1) == tuple(mine)
      assert n1.context.validity_cache.snapshot.quorum_status == QUORUM_HEALTHY
      assert n1.manager.flags.get("node2", 0) >= 1

  run(go())


# ------------------------------------------------------- PoW mining vs a sync replace


def test_sync_replace_abandons_pow_mining_and_restarts_on_the_adopted_tip(
  node_env: NodeEnv, caplog: pytest.LogCaptureFixture
) -> None:
  # CN-TC-17.3 (PoW half) / CN-TC-3.13: no corrupted state, mining resumes on the new tip
  slow_sync_env(node_env)
  theirs = pow_chain(node_env, 3)

  async def go() -> None:
    async with Cluster(
      node_env, ids=("node1", "node2"), mine=True, register_peers=False
    ) as cluster:
      n1, n2 = cluster["node1"], cluster["node2"]
      await install(n2, theirs)
      n1.engine._target = 0  # an attempt that can only end by being interrupted
      record = _record(node_env, 50)
      n1.context.mempool.add(record)
      n1.engine.on_submission(record)
      await asyncio.sleep(0.1)
      assert n1.tip == 0  # still mining on the genesis

      with caplog.at_level(logging.INFO, logger="node.pow"):
        assert await sync_of(n1).sync_with(peer_of(n2)) == "adopted"
        await until(lambda: "abandoned" in caplog.text, timeout=2.0)

      assert blocks_of(n1) == tuple(theirs)
      snapshot = n1.context.validity_cache.snapshot
      assert snapshot.chain_valid and snapshot.tip_index == 3  # the cache reflects the new chain
      assert n1.context.mempool.contains(record.document_hash)  # our batch is still pending
      assert n1.tip == 3  # an abandoned attempt appends nothing

      n1.engine._target = pow_target(1)  # the difficulty is reachable again
      await until(lambda: n1.tip == 4)
      mined = blocks_of(n1)[4]
      assert mined.previous_hash == theirs[3].block_hash  # on the ADOPTED tip
      assert [r.document_hash for r in mined.document_records] == [record.document_hash]
      assert n1.context.validator.full(blocks_of(n1)).valid
      assert n1.context.validity_cache.snapshot.tip_index == 4
      assert len(n1.context.mempool) == 0 and cluster.stored_blocks("node1")[4] == mined

  run(go())


def test_records_of_dropped_local_blocks_are_requeued_and_mined_again(node_env: NodeEnv) -> None:
  # CN-TC-17.3 (PoW half): an acknowledged submission is never lost by a fork switch
  slow_sync_env(node_env)
  theirs = extend(node_env, [GENESIS], [21, 22, 23])

  async def go() -> None:
    async with Cluster(
      node_env, ids=("node1", "node2"), mine=True, register_peers=False
    ) as cluster:
      n1, n2 = cluster["node1"], cluster["node2"]
      await install(n2, theirs)
      record = _record(node_env, 7)
      n1.context.mempool.add(record)
      n1.engine.on_submission(record)
      await until(lambda: n1.tip == 1)  # mined locally: our fork
      assert n1.context.documents.contains(record.document_hash)

      assert await sync_of(n1).sync_with(peer_of(n2)) == "adopted"  # the longer fork wins

      await until(lambda: n1.tip == 4)  # the dropped record is mined on top of the adopted tip
      final = blocks_of(n1)
      assert final[:4] == tuple(theirs)
      assert [r.document_hash for r in final[4].document_records] == [record.document_hash]
      assert n1.context.validator.full(final).valid
      assert n1.context.documents.block_indexes(record.document_hash) == [4]

  run(go())
