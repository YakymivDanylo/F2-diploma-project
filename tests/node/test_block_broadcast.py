from __future__ import annotations

import asyncio
import logging
import re
import socket
import threading
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
import uvicorn
from chain_factory import _record, pow_block
from network_helpers import Cluster, ClusterNode, until
from node_helpers import NodeEnv, pem_of

from blockchain_core import (
  Block,
  generate_node_keypair,
  sha256_hex,
)
from blockchain_core.storage.chain_store import block_to_dict
from node.config import load_config
from node.main import create_app

SRC = Path(__file__).resolve().parents[2] / "src" / "node"


def run(coro: Any) -> Any:
  return asyncio.run(coro)


def _pend(node: ClusterNode, seed: int) -> str:
  record = _record(_ENV[0], seed)
  node.context.mempool.add(record)
  node.engine.on_submission(record)
  return record.document_hash


_ENV: list[NodeEnv] = []


@pytest.fixture(autouse=True)
def _remember_env(node_env: NodeEnv):
  _ENV[:] = [node_env]
  yield
  _ENV.clear()


def _spy_broadcasts(node: ClusterNode) -> list[dict]:
  sent: list[dict] = []
  original = node.manager.broadcast

  async def spy(message):
    sent.append(message)
    return await original(message)

  node.manager.broadcast = spy  # type: ignore[method-assign]
  return sent


def _genesis(node: ClusterNode) -> Block:
  return node.context.current_blocks()[0]


# ------------------------------------------------------------------ happy path


def test_mined_block_reaches_every_peer(node_env: NodeEnv) -> None:  # CN-TC-7.1
  async def go():
    async with Cluster(node_env) as cluster:
      await cluster.all_connected()
      digest = _pend(cluster["node1"], 1)
      await until(lambda: all(n.tip == 1 for n in cluster.nodes.values()))
      hashes = {n.context.current_blocks()[1].block_hash for n in cluster.nodes.values()}
      assert len(hashes) == 1  # everyone converged on the identical block
      for node in cluster.nodes.values():
        assert node.context.validator.full(node.context.current_blocks()).valid
        assert node.context.documents.contains(digest)
        assert node.context.validity_cache.snapshot.tip_index == 1
      # fast path: peers appended without ever fetching the chain
      assert cluster["node2"].receiver.needs_sync == []
      assert len(cluster.stored_blocks("node3")) == 2  # persisted on the receiver, too

  run(go())


def test_blocks_flow_in_both_directions(node_env: NodeEnv) -> None:  # CN-TC-7.1 / 6.6
  async def go():
    async with Cluster(node_env, ids=("node1", "node2")) as cluster:
      await cluster.all_connected()
      _pend(cluster["node1"], 1)
      await until(lambda: cluster["node2"].tip == 1)
      _pend(cluster["node2"], 2)  # the other way round, on top of the adopted block
      await until(lambda: cluster["node1"].tip == 2)
      assert cluster["node1"].context.current_blocks()[2].proposer_id == "node2"

  run(go())


def test_a_peer_that_missed_a_block_is_told_to_sync(node_env: NodeEnv) -> None:  # CN-TC-7.4
  async def go():
    async with Cluster(node_env, ids=("node1", "node2")) as cluster:
      await cluster.all_connected()
      n1, n2 = cluster["node1"], cluster["node2"]
      first = pow_block(node_env, _genesis(n1), 1)
      second = pow_block(node_env, first, 2)
      verdict = n2.receiver.handle_block("node1", block_to_dict(second))  # skipping #1
      assert verdict.kind == "needs_sync"
      assert n2.tip == 0 and n2.receiver.needs_sync == ["node1"]  # logged, nothing appended

  run(go())


# ---------------------------------------------------------------- rejections


def _reject_case(node_env: NodeEnv, build, expected: str, *, flagged: bool = True) -> None:
  async def go():
    async with Cluster(node_env) as cluster:
      await cluster.all_connected()
      target, sender = cluster["node2"], cluster["node1"]
      relays = _spy_broadcasts(target)
      block = build(cluster)
      verdict = target.receiver.handle_block("node1", block_to_dict(block))
      assert verdict.kind == "reject" and verdict.reason == expected
      assert target.tip == 0  # never appended
      assert relays == []  # never re-broadcast
      assert (target.manager.flags.get("node1", 0) == 1) is flagged
      assert sender.tip == 0

  run(go())


def test_unsigned_block_is_rejected(node_env: NodeEnv) -> None:  # CN-TC-8.2
  for missing in (None, ""):
    _reject_case(
      node_env,
      lambda c, m=missing: replace(
        pow_block(node_env, _genesis(c["node1"]), 1), proposer_signature=m
      ),
      "unsigned",
    )


def test_unknown_signer_is_rejected(node_env: NodeEnv) -> None:  # CN-TC-8.3 / 8.6
  stranger = generate_node_keypair()

  def unknown_id(cluster):
    return pow_block(node_env, _genesis(cluster["node1"]), 1, proposer="mallory", signer=stranger)

  _reject_case(node_env, unknown_id, "unknown_proposer")

  def forged(cluster):  # claims to be node1 but is signed by somebody else
    return pow_block(node_env, _genesis(cluster["node1"]), 1, proposer="node1", signer=stranger)

  _reject_case(node_env, forged, "bad_signature")


def test_a_peerinfo_only_node_cannot_author_blocks(node_env: NodeEnv) -> None:  # CN-TC-8.6
  # Registered for connectivity (PeerInfo) but absent from the ValidatorSet: its blocks could
  # not be re-validated by any other node, so they are refused as unknown.
  outsider = generate_node_keypair()

  def build(cluster):
    node = cluster["node2"]
    node.context.peers.register("outsider", "outsider", 9999, pem_of(outsider))
    return pow_block(node_env, _genesis(node), 1, proposer="outsider", signer=outsider)

  _reject_case(node_env, build, "unknown_proposer")


def test_broken_link_is_rejected(node_env: NodeEnv) -> None:  # CN-TC-8.4
  def wrong_parent(cluster):
    fake_parent = replace(_genesis(cluster["node1"]), block_hash=sha256_hex(b"somewhere else"))
    return pow_block(node_env, fake_parent, 1)  # correctly signed, but previous_hash is wrong

  _reject_case(node_env, wrong_parent, "link")


def test_inconsistent_merkle_root_is_rejected(node_env: NodeEnv) -> None:  # CN-TC-8.4
  def swapped_records(cluster):
    block = pow_block(node_env, _genesis(cluster["node1"]), 1)
    return replace(block, document_records=(_record(node_env, 99),))  # root no longer matches

  _reject_case(node_env, swapped_records, "merkle")


def test_wrong_difficulty_is_rejected(node_env: NodeEnv) -> None:
  _reject_case(
    node_env,
    lambda c: pow_block(node_env, _genesis(c["node1"]), 1, difficulty=2),
    "difficulty",
  )


def test_far_future_block_is_rejected(node_env: NodeEnv) -> None:
  def build(cluster):
    cluster["node2"].context.gateway._now_ms = lambda: 0  # the block looks decades ahead
    return pow_block(node_env, _genesis(cluster["node1"]), 1)

  _reject_case(node_env, build, "timestamp_in_future")


def test_malformed_traffic_is_flagged(node_env: NodeEnv) -> None:
  async def go():
    async with Cluster(node_env, ids=("node1", "node2")) as cluster:
      receiver = cluster["node2"].receiver
      await receiver.on_message("node1", {"type": "block", "block": {"index": 1}})
      await receiver.on_message("node1", {"type": "surprise"})
      await receiver.on_message("node1", {"type": "block"})
      assert cluster["node2"].manager.flags["node1"] == 3
      assert cluster["node2"].tip == 0

  run(go())


# ------------------------------------------- duplicates, conflicts, concurrency


def test_duplicate_delivery_is_a_no_op(node_env: NodeEnv) -> None:  # CN-TC-7.5
  async def go():
    async with Cluster(node_env, ids=("node1", "node2")) as cluster:
      n2 = cluster["node2"]
      block = pow_block(node_env, _genesis(n2), 1)
      payload = block_to_dict(block)
      assert n2.receiver.handle_block("node1", payload).kind == "accept"
      again = n2.receiver.handle_block("node1", payload)  # e.g. via the other connection
      assert again.kind == "duplicate"
      assert n2.tip == 1 and n2.manager.flags == {}  # no error, no flag
      assert len(cluster.stored_blocks("node2")) == 2

  run(go())


def test_simultaneous_fan_in_keeps_state_consistent(node_env: NodeEnv) -> None:  # CN-TC-7.6
  async def go():
    async with Cluster(node_env, ids=("node1", "node2")) as cluster:
      n2 = cluster["node2"]
      block = pow_block(node_env, _genesis(n2), 1)
      rival = pow_block(
        node_env, _genesis(n2), 2, proposer="node3", signer=node_env.validator_keys["node3"]
      )
      messages = [{"type": "block", "block": block_to_dict(block)}] * 40
      messages += [{"type": "block", "block": block_to_dict(rival)}] * 40
      await asyncio.gather(*(n2.receiver.on_message(f"p{i}", m) for i, m in enumerate(messages)))
      blocks = n2.context.current_blocks()
      assert len(blocks) == 2  # exactly one winner at that height
      assert blocks[1].block_hash in (block.block_hash, rival.block_hash)
      assert n2.context.validator.full(blocks).valid
      assert n2.context.validity_cache.snapshot.tip_index == 1
      assert [b.block_hash for b in cluster.stored_blocks("node2")] == [
        b.block_hash for b in blocks
      ]

  run(go())


def test_same_proposer_signing_twice_is_an_equivocation(node_env: NodeEnv, caplog) -> None:
  async def go():  # CN-TC-8.5: first-finalized wins; the same proposer signing two blocks is logged
    async with Cluster(node_env, ids=("node1", "node2")) as cluster:
      n2 = cluster["node2"]
      first = pow_block(node_env, _genesis(n2), 1)
      assert n2.receiver.handle_block("node1", block_to_dict(first)).kind == "accept"
      second = pow_block(node_env, _genesis(n2), 2)  # node1 again, a different block, same height
      with caplog.at_level(logging.WARNING, logger="node.validation"):
        verdict = n2.receiver.handle_block("node1", block_to_dict(second))
      assert (verdict.kind, verdict.reason, verdict.equivocation) == ("reject", "conflict", True)
      assert "equivocation" in caplog.text
      assert n2.context.current_blocks()[1].block_hash == first.block_hash  # first one stays

  run(go())


def test_two_miners_at_one_height_is_a_fork_not_equivocation(node_env: NodeEnv, caplog) -> None:
  async def go():  # an ordinary PoW race must not be reported as a Byzantine event
    async with Cluster(node_env, ids=("node1", "node2", "node3")) as cluster:
      n2 = cluster["node2"]
      first = pow_block(node_env, _genesis(n2), 1)
      assert n2.receiver.handle_block("node1", block_to_dict(first)).accepted
      rival = pow_block(
        node_env, _genesis(n2), 2, proposer="node3", signer=node_env.validator_keys["node3"]
      )
      with caplog.at_level(logging.WARNING, logger="node.validation"):
        verdict = n2.receiver.handle_block("node3", block_to_dict(rival))
      assert (verdict.reason, verdict.equivocation) == ("conflict", False)
      assert "equivocation" not in caplog.text

  run(go())


def test_doctored_hash_is_neither_a_duplicate_nor_an_equivocation(
  node_env: NodeEnv, caplog
) -> None:
  async def go():  # block_hash is outside the signature: a relayer must not be able to abuse it
    async with Cluster(node_env, ids=("node1", "node2")) as cluster:
      n2 = cluster["node2"]
      first = pow_block(node_env, _genesis(n2), 1)
      assert n2.receiver.handle_block("node1", block_to_dict(first)).accepted
      other = pow_block(node_env, _genesis(n2), 2)  # genuinely different block, same proposer
      disguised = replace(other, block_hash=first.block_hash)  # claims to be the stored one
      with caplog.at_level(logging.WARNING, logger="node.validation"):
        verdict = n2.receiver.handle_block("node1", block_to_dict(disguised))
      assert verdict.kind == "reject" and verdict.reason == "hash"
      assert not verdict.equivocation and "equivocation" not in caplog.text

  run(go())


def test_a_forged_conflict_is_not_an_equivocation(node_env: NodeEnv, caplog) -> None:
  async def go():
    async with Cluster(node_env, ids=("node1", "node2")) as cluster:
      n2 = cluster["node2"]
      assert n2.receiver.handle_block(
        "node1", block_to_dict(pow_block(node_env, _genesis(n2), 1))
      ).accepted
      stranger = generate_node_keypair()
      forged = pow_block(node_env, _genesis(n2), 2, proposer="node3", signer=stranger)
      with caplog.at_level(logging.WARNING, logger="node.validation"):
        verdict = n2.receiver.handle_block("node1", block_to_dict(forged))
      assert verdict.reason == "bad_signature" and not verdict.equivocation
      assert "equivocation" not in caplog.text  # nobody can frame node3 with a bad signature

  run(go())


def test_stale_replay_is_not_reprocessed(node_env: NodeEnv) -> None:  # CN-TC-8.7
  async def go():
    async with Cluster(node_env, ids=("node1", "node2")) as cluster:
      n2 = cluster["node2"]
      chain = [_genesis(n2)]
      for seed in (1, 2, 3):
        chain.append(pow_block(node_env, chain[-1], seed))
        assert n2.receiver.handle_block("node1", block_to_dict(chain[-1])).accepted
      old_other = pow_block(node_env, chain[0], 7)  # a different block for finalized index 1
      assert n2.receiver.handle_block("node1", block_to_dict(old_other)).reason == "conflict"
      assert n2.receiver.handle_block("node1", block_to_dict(chain[1])).kind == "duplicate"
      assert n2.tip == 3

  run(go())


def test_pbft_node_screens_but_does_not_adopt(node_env: NodeEnv) -> None:
  async def go():
    async with Cluster(node_env, ids=("node1", "node2"), mode="pbft") as cluster:
      n2 = cluster["node2"]
      assert n2.engine is None  # PBFT adoption arrives with Slice 17
      verdict = n2.receiver.handle_block(
        "node1", block_to_dict(pow_block(node_env, _genesis(n2), 1))
      )
      assert verdict.kind == "reject" and n2.tip == 0  # a PoW block never fits a PBFT chain

  run(go())


# ------------------------------------------------------------------- static


def test_exactly_one_validation_entry_point() -> None:
  # CN-TC-8.1 / FR-25: only validation_gateway.py may reach the core validators.
  pattern = re.compile(r"\b(validate_chain|validate_extension)\b")
  users = sorted(
    path.name for path in SRC.rglob("*.py") if pattern.search(path.read_text(encoding="utf-8"))
  )
  assert users == ["validation_gateway.py"]


def test_no_trusted_peer_shortcut() -> None:
  text = (SRC / "network" / "ws_blocks.py").read_text(encoding="utf-8")
  assert "self._gateway.screen(block)" in text  # every inbound block is screened
  assert not re.search(r"\b(trusted|whitelist|skip_validation)\b", text, re.IGNORECASE)


# ---------------------------------------------------------- real sockets (smoke)


def _free_port() -> int:
  with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    return int(sock.getsockname()[1])


def test_blocks_travel_over_real_websockets(node_env: NodeEnv) -> None:
  port = _free_port()
  env_a = {
    **node_env.env,
    "NODE_ID": "node1",
    "CONSENSUS_MODE": "pow",
    "EXPECTED_DIFFICULTY": "1",
    "CHAIN_PATH": str(node_env.root / "real-a.json"),
  }
  app_a = create_app(load_config(env_a))  # engine on: it is what adopts peer blocks
  server = uvicorn.Server(uvicorn.Config(app_a, host="127.0.0.1", port=port, log_level="warning"))
  thread = threading.Thread(target=server.run, daemon=True)
  thread.start()
  try:
    deadline = 100
    while not server.started and deadline:
      threading.Event().wait(0.05)
      deadline -= 1
    assert server.started

    from node_helpers import pem_of as _pem  # node2's own key material

    from blockchain_core import save_key_pair

    key_path = node_env.root / "keys" / "node2.pem"
    save_key_pair(node_env.validator_keys["node2"], key_path)
    env_b = {
      **env_a,
      "NODE_ID": "node2",
      "NODE_KEY_PATH": str(key_path),
      "CHAIN_PATH": str(node_env.root / "real-b.json"),
    }

    async def go() -> None:
      app_b = create_app(
        load_config(env_b), network_options={"scan_interval": 0.05, "base_delay": 0.05}
      )
      async with app_b.router.lifespan_context(app_b):
        context_b = app_b.state.context
        context_b.peers.register("node1", "127.0.0.1", port, _pem(node_env.validator_keys["node1"]))
        await until(lambda: app_b.state.manager.health().get("node1") == "up", timeout=10)
        record = _record(node_env, 1)
        context_b.mempool.add(record)
        app_b.state.engine.on_submission(record)
        await until(lambda: len(app_a.state.context.current_blocks()) == 2, timeout=10)
        mined = context_b.current_blocks()[1]
        assert app_a.state.context.current_blocks()[1].block_hash == mined.block_hash

    asyncio.run(go())
  finally:
    server.should_exit = True
    thread.join(timeout=10)
