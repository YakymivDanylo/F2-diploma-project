from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from chain_factory import _record, pow_block
from fastapi.testclient import TestClient
from node_helpers import NodeEnv

from blockchain_core import (
  Block,
  JsonChainStore,
  pow_target,
  sha256_hex,
  verify_proof,
)
from node.config import load_config
from node.consensus.pow import PowEngine
from node.context import NodeContext, build_node_context
from node.main import create_app


def _env(node_env: NodeEnv, difficulty: int = 1, mode: str = "pow") -> dict[str, str]:
  env = {**node_env.env, "CONSENSUS_MODE": mode}
  if mode == "pow":
    env["EXPECTED_DIFFICULTY"] = str(difficulty)
  return env


def _serve(env: dict[str, str]) -> Iterator[tuple[TestClient, NodeContext]]:
  app = create_app(load_config(env))
  with TestClient(app) as client:
    yield client, app.state.context


def _wait(condition: Callable[[], bool], timeout: float = 10.0) -> None:
  deadline = time.monotonic() + timeout
  while not condition():
    assert time.monotonic() < deadline, "condition not reached in time"
    time.sleep(0.01)


def _hash(seed: int) -> str:
  return sha256_hex(f"document-{seed}".encode())


def _post(client: TestClient, seed: int):
  return client.post("/documents", json={"hash": _hash(seed), "metadata": {"seed": seed}})


def _tip(client: TestClient) -> int:
  return client.get("/node/info").json()["tip_index"]


def test_mined_block_is_valid_and_attested(node_env: NodeEnv) -> None:  # CN-TC-5.1
  for client, context in _serve(_env(node_env, difficulty=8)):
    assert _post(client, 1).status_code == 202
    _wait(lambda client=client: _tip(client) == 1)
    block = context.current_blocks()[1]
    assert block.algorithm == "pow" and block.proposer_id == "node1"
    assert block.sealed_consensus["difficulty"] == 8
    assert int(block.block_hash, 16) < pow_target(8)
    assert block.proposer_signature
    assert context.validator.full(context.current_blocks()).valid  # Slice 6/7 validation
    info = client.get("/node/info").json()
    assert info["chain_valid"] is True and info["tip_index"] == 1
    assert len(context.mempool) == 0  # de-queued once finalized
    found = client.get(f"/documents/{_hash(1)}")  # the live chain is what lookups see
    assert found.status_code == 200 and found.json()["block_index"] == 1
    assert client.post("/documents", json={"hash": _hash(1), "metadata": {}}).status_code == 409


def test_pending_batch_is_mined_together(node_env: NodeEnv) -> None:
  for client, context in _serve(_env(node_env)):
    for seed in (1, 2, 3):
      assert _post(client, seed).status_code == 202
    _wait(lambda context=context: len(context.mempool) == 0)
    blocks = context.current_blocks()
    mined = [r.document_hash for block in blocks[1:] for r in block.document_records]
    assert sorted(mined) == sorted(_hash(s) for s in (1, 2, 3))
    assert context.validator.full(blocks).valid


def test_block_is_persisted(node_env: NodeEnv) -> None:  # CN-TC-5.1: finalized locally
  for client, _ in _serve(_env(node_env)):
    _post(client, 1)
    _wait(lambda client=client: _tip(client) == 1)
  store = JsonChainStore(node_env.env["CHAIN_PATH"])
  try:
    stored = store.load()
  finally:
    store.close()
  assert stored is not None and len(stored) == 2 and stored[1].algorithm == "pow"


def _run(node_env: NodeEnv, scenario: Callable[[NodeContext, PowEngine], Any], **options: Any):
  async def go() -> Any:
    context = build_node_context(load_config(_env(node_env)))
    engine = PowEngine(context, **options)
    try:
      await engine.start()
      return await scenario(context, engine)
    finally:
      await engine.stop()
      context.store.close()

  return asyncio.run(go())


async def _until(condition: Callable[[], bool], timeout: float = 10.0) -> None:
  deadline = time.monotonic() + timeout
  while not condition():
    assert time.monotonic() < deadline, "condition not reached in time"
    await asyncio.sleep(0.005)


def _pend(context: NodeContext, engine: PowEngine, seed: int) -> str:
  record = _record(_NODE_ENV[0], seed)
  context.mempool.add(record)
  engine.on_submission(record)
  return record.document_hash


_NODE_ENV: list[NodeEnv] = []


@pytest.fixture(autouse=True)
def _remember_env(node_env: NodeEnv) -> Iterator[None]:
  _NODE_ENV[:] = [node_env]
  yield
  _NODE_ENV.clear()


def test_competing_block_aborts_mining_and_requeues(node_env: NodeEnv, caplog) -> None:
  # CN-TC-5.3 / 5.7: a never-satisfied target stands in for "extremely high difficulty"
  async def scenario(context: NodeContext, engine: PowEngine) -> None:
    engine._target = 0  # nothing can ever meet it: the loop only ends by being interrupted
    mine_hash = _pend(context, engine, 1)
    await asyncio.sleep(0.1)
    assert context.current_blocks()[-1].index == 0  # still mining, nothing finalized
    assert len(context.metrics) == 0  # an in-flight attempt is not a metric (9.4)

    peer = pow_block(node_env, context.current_blocks()[-1], seed=2, difficulty=1)
    with caplog.at_level(logging.INFO, logger="node.pow"):
      assert await engine.on_inbound_block(peer) is True
      await _until(lambda: "abandoned" in caplog.text, timeout=2.0)  # within one poll
    assert context.documents.contains(_hash(2))
    assert context.mempool.contains(mine_hash)  # our batch was not included: re-queued

    engine._target = pow_target(1)  # the difficulty is reachable again
    engine.on_submission(context.mempool.snapshot()[0])
    await _until(lambda: len(context.current_blocks()) == 3)
    assert [r.document_hash for r in context.current_blocks()[2].document_records] == [mine_hash]
    assert len(context.mempool) == 0
    assert context.validator.full(context.current_blocks()).valid

  _run(node_env, scenario, attempts_per_poll=50)


def test_competing_block_with_our_record_dequeues_it(node_env: NodeEnv) -> None:  # 5.3
  async def scenario(context: NodeContext, engine: PowEngine) -> None:
    engine._target = 0
    _pend(context, engine, 1)
    await asyncio.sleep(0.05)
    peer = pow_block(node_env, context.current_blocks()[-1], seed=1, difficulty=1)
    assert await engine.on_inbound_block(peer) is True
    assert len(context.mempool) == 0  # included in the winning block: nothing to re-queue
    assert context.documents.contains(_hash(1))

  _run(node_env, scenario, attempts_per_poll=50)


def test_inbound_block_must_extend_the_tip_and_validate(node_env: NodeEnv) -> None:
  async def scenario(context: NodeContext, engine: PowEngine) -> None:
    genesis = context.current_blocks()[0]
    good = pow_block(node_env, genesis, seed=5, difficulty=1)
    unsigned = Block(**{**good.__dict__, "proposer_signature": None})
    assert await engine.on_inbound_block(unsigned) is False  # fails validation
    wrong_diff = pow_block(node_env, genesis, seed=6, difficulty=2)
    assert await engine.on_inbound_block(wrong_diff) is False
    assert await engine.on_inbound_block(good) is True
    assert await engine.on_inbound_block(good) is False  # already the tip: not a new extension
    stale = pow_block(node_env, genesis, seed=7, difficulty=1)
    assert await engine.on_inbound_block(stale) is False  # a fork at the same height
    assert len(context.current_blocks()) == 2

  _run(node_env, scenario)


def test_finalized_records_are_dropped_from_the_batch(node_env: NodeEnv) -> None:
  async def scenario(context: NodeContext, engine: PowEngine) -> None:
    engine._target = 0
    _pend(context, engine, 1)
    await asyncio.sleep(0.05)
    peer = pow_block(node_env, context.current_blocks()[-1], seed=1, difficulty=1)
    await engine.on_inbound_block(peer)
    context.mempool.add(_record(node_env, 1))  # the same hash sneaks back in
    engine._target = pow_target(1)
    engine.on_submission(_record(node_env, 1))
    await _until(lambda: len(context.mempool) == 0)
    assert len(context.current_blocks()) == 2  # nothing mined for a finalized hash

  _run(node_env, scenario, attempts_per_poll=50)


def test_on_block_mined_hook_receives_the_block(node_env: NodeEnv) -> None:  # broadcast seam
  seen: list[Block] = []

  async def hook(block: Block) -> None:
    seen.append(block)

  async def scenario(context: NodeContext, engine: PowEngine) -> None:
    _pend(context, engine, 1)
    await _until(lambda: len(seen) == 1)
    assert seen[0] is context.current_blocks()[1]

  _run(node_env, scenario, on_block_mined=hook)


def test_mined_proof_verifies(node_env: NodeEnv) -> None:
  for client, _ in _serve(_env(node_env)):
    _post(client, 4)
    _wait(lambda client=client: _tip(client) == 1)
    body = client.get(f"/documents/{_hash(4)}").json()
    assert body["chain_valid"] is True
    from blockchain_core import DocumentRecord, ProofStep

    proof = [ProofStep(s["position"], s["sibling_hash"]) for s in body["merkle_proof"]]
    assert verify_proof(DocumentRecord(**body["record"]), proof, body["merkle_root"])


def test_no_pow_engine_under_pbft(node_env: NodeEnv) -> None:
  app = create_app(load_config(_env(node_env, mode="pbft")))
  with TestClient(app) as client:
    assert not isinstance(app.state.engine, PowEngine)  # the PBFT engine runs instead
    assert client.get("/node/info").json()["algorithm"] == "pbft"


def test_engine_stops_cleanly(node_env: NodeEnv) -> None:
  async def scenario(context: NodeContext, engine: PowEngine) -> None:
    engine._target = 0
    _pend(context, engine, 1)
    await asyncio.sleep(0.05)

  _run(node_env, scenario, attempts_per_poll=50)  # finishing without hanging is the assertion


def test_engine_rejects_nonsense_options(node_env: NodeEnv, boot) -> None:
  context = boot(_env(node_env))
  with pytest.raises(ValueError):
    PowEngine(context, attempts_per_poll=0)
  with pytest.raises(ValueError):
    PowEngine(context, max_batch=0)
  other = {**_env(node_env, mode="pbft"), "CHAIN_PATH": str(node_env.root / "other.json")}
  pbft = boot(other)
  with pytest.raises(ValueError):
    PowEngine(pbft)
